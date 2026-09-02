<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Client;

use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Crypto\Artifacts;
use Byfareska\Hawk\Crypto\Crypto;
use Byfareska\Hawk\Exception\InvalidArgumentException;
use Byfareska\Hawk\Header\Header;
use Byfareska\Hawk\Header\HeaderFactory;
use Byfareska\Hawk\Nonce\NonceProviderInterface;
use Byfareska\Hawk\Time\TimeProviderInterface;

/**
 * Strona podpisująca protokołu Hawk.
 */
final readonly class Client implements ClientInterface
{
    public function __construct(
        private Crypto $crypto,
        private TimeProviderInterface $timeProvider,
        private NonceProviderInterface $nonceProvider,
        private int $localtimeOffset,
    ) {
    }

    /**
     * @param array{timestamp?: int, nonce?: string, payload?: string, content_type?: string, ext?: string, app?: string, dlg?: string} $options
     */
    public function createRequest(
        CredentialsInterface $credentials,
        string $uri,
        string $method,
        array $options = [],
    ): Request {
        $timestamp = $this->timestamp($options);
        [$host, $port, $resource] = $this->parseUri($uri);

        $nonce = $options['nonce'] ?? $this->nonceProvider->createNonce();

        [$payload, $contentType, $hash] = $this->resolvePayloadOptions($credentials, $options);

        $ext = $options['ext'] ?? null;
        $app = $options['app'] ?? null;
        $dlg = $options['dlg'] ?? null;

        $artifacts = new Artifacts(
            $method,
            $host,
            $port,
            $resource,
            $timestamp,
            $nonce,
            $ext,
            $payload,
            $contentType,
            $hash,
            $app,
            $dlg,
        );

        $attributes = [
            'id' => $credentials->id() ?? '',
            'ts' => $artifacts->timestamp(),
            'nonce' => $artifacts->nonce(),
        ];

        if (null !== $hash) {
            $attributes['hash'] = $hash;
        }

        if (null !== $ext) {
            $attributes['ext'] = $ext;
        }

        $attributes['mac'] = $this->crypto->calculateMac('header', $credentials, $artifacts);

        if (null !== $app) {
            $attributes['app'] = $app;
        }

        if (null !== $dlg) {
            $attributes['dlg'] = $dlg;
        }

        return new Request(HeaderFactory::create('Authorization', $attributes), $artifacts);
    }

    /**
     * @param array{payload?: string, content_type?: string} $options
     */
    public function authenticate(
        CredentialsInterface $credentials,
        Request $request,
        Header|string $headerObjectOrString,
        array $options = [],
    ): bool {
        $header = HeaderFactory::createFromHeaderObjectOrString(
            'Server-Authorization',
            $headerObjectOrString,
            static function (): never {
                throw new InvalidArgumentException(\sprintf(
                    'Header must either be a string or an instance of %s.',
                    Header::class,
                ));
            },
        );

        $hasPayload = isset($options['payload']);
        $hasContentType = isset($options['content_type']);

        if ($hasPayload !== $hasContentType) {
            throw new InvalidArgumentException(
                'If one of "payload" and "content_type" are specified, both must be specified.',
            );
        }

        $payload = $options['payload'] ?? null;
        $contentType = $options['content_type'] ?? null;

        $artifacts = new Artifacts(
            $request->artifacts()->method(),
            $request->artifacts()->host(),
            $request->artifacts()->port(),
            $request->artifacts()->resource(),
            $request->artifacts()->timestamp(),
            $request->artifacts()->nonce(),
            $header->attribute('ext'),
            $payload,
            $contentType,
            $header->attribute('hash'),
            $request->artifacts()->app(),
            $request->artifacts()->dlg(),
        );

        // hash_equals, nie !== — porównanie stringów w PHP kończy się na pierwszym różnym
        // bajcie, więc czas odpowiedzi mówi, ile początkowych bajtów MAC-a zgadło się
        // z prawidłowym. Oryginał porównywał tu wprost operatorem.
        if (!hash_equals($this->crypto->calculateMac('response', $credentials, $artifacts), $header->attribute('mac') ?? '')) {
            return false;
        }

        if (null === $payload) {
            return true;
        }

        $hash = $artifacts->hash();
        if (null === $hash) {
            return false;
        }

        \assert(null !== $contentType);

        return hash_equals(
            $this->crypto->calculatePayloadHash($payload, $credentials->algorithm(), $contentType),
            $hash,
        );
    }

    /**
     * @param array{timestamp?: int, ext?: string} $options
     */
    public function createBewit(
        CredentialsInterface $credentials,
        string $uri,
        int $ttlSec,
        array $options = [],
    ): string {
        $timestamp = $this->timestamp($options);
        [$host, $port, $resource] = $this->parseUri($uri);

        $ext = $options['ext'] ?? null;
        $id = $credentials->id() ?? '';

        // Bewit to cztery pola sklejone backslashem, więc backslash w id albo w ext
        // rozjeżdża podział po stronie serwera. Oryginał sklejał je bez sprawdzenia
        // i po cichu produkował podpis, którego nikt nie umiał rozparsować.
        $this->assertBewitField('credentials id', $id);
        if (null !== $ext) {
            $this->assertBewitField('ext', $ext);
        }

        $exp = $timestamp + $ttlSec;

        $artifacts = new Artifacts(
            'GET',
            $host,
            $port,
            $resource,
            $exp,
            '',
            $ext,
        );

        $bewit = implode('\\', [
            $id,
            $exp,
            $this->crypto->calculateMac('bewit', $credentials, $artifacts),
            $ext ?? '',
        ]);

        return rtrim(strtr(base64_encode($bewit), '+/', '-_'), '=');
    }

    /**
     * @param array{timestamp?: int} $options
     */
    private function timestamp(array $options): int
    {
        return ($options['timestamp'] ?? $this->timeProvider->createTimestamp()) + $this->localtimeOffset;
    }

    /**
     * @return array{string, int, string} host, port, zasób (ścieżka z query stringiem)
     */
    private function parseUri(string $uri): array
    {
        $parsed = parse_url($uri);

        // Hawk podpisuje host i port, więc adres względny nie ma czego podpisać. Oryginał
        // sięgał tu po $parsed['host'] bez sprawdzenia: wychodził warning i pusty host,
        // czyli podpis, którego żaden serwer nie potwierdzi.
        if (false === $parsed || !isset($parsed['host']) || !isset($parsed['scheme'])) {
            throw new InvalidArgumentException(\sprintf(
                'Hawk can only sign an absolute URI with a scheme and a host, got "%s".',
                $uri,
            ));
        }

        $resource = $parsed['path'] ?? '';
        if (isset($parsed['query'])) {
            $resource .= '?' . $parsed['query'];
        }

        $port = $parsed['port'] ?? ('https' === $parsed['scheme'] ? 443 : 80);

        return [$parsed['host'], $port, $resource];
    }

    /**
     * @param array{payload?: string, content_type?: string} $options
     *
     * @return array{string|null, string|null, string|null}
     */
    private function resolvePayloadOptions(CredentialsInterface $credentials, array $options): array
    {
        $hasPayload = isset($options['payload']);
        $hasContentType = isset($options['content_type']);

        if (!$hasPayload && !$hasContentType) {
            return [null, null, null];
        }

        if (!$hasPayload || !$hasContentType) {
            throw new InvalidArgumentException(
                'If one of "payload" and "content_type" are specified, both must be specified.',
            );
        }

        $payload = $options['payload'];
        $contentType = $options['content_type'];

        return [
            $payload,
            $contentType,
            $this->crypto->calculatePayloadHash($payload, $credentials->algorithm(), $contentType),
        ];
    }

    private function assertBewitField(string $name, string $value): void
    {
        if (str_contains($value, '\\')) {
            throw new InvalidArgumentException(\sprintf(
                'Hawk %s must not contain a backslash; it is the bewit field separator.',
                $name,
            ));
        }
    }
}
