<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Server;

use Byfareska\Hawk\Credentials\CallbackCredentialsProvider;
use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Credentials\CredentialsProviderInterface;
use Byfareska\Hawk\Crypto\Artifacts;
use Byfareska\Hawk\Crypto\Crypto;
use Byfareska\Hawk\Exception\InvalidArgumentException;
use Byfareska\Hawk\Header\Header;
use Byfareska\Hawk\Header\HeaderFactory;
use Byfareska\Hawk\Nonce\CallbackNonceValidator;
use Byfareska\Hawk\Nonce\NonceValidatorInterface;
use Byfareska\Hawk\Time\TimeProviderInterface;

/**
 * Strona weryfikująca protokołu Hawk.
 *
 * Wszystko, co przychodzi z żądania, jest tu danymi wroga: żadna ścieżka nie może skończyć
 * się błędem PHP zamiast odmowy. Zniekształcone wejście ma dać UnauthorizedException,
 * a nie TypeError — bo TypeError to 500, a 500 zdradza więcej niż 401.
 */
final readonly class Server implements ServerInterface
{
    private CredentialsProviderInterface $credentialsProvider;
    private NonceValidatorInterface $nonceValidator;

    /**
     * @param CredentialsProviderInterface|callable(?string): ?CredentialsInterface $credentialsProvider
     * @param NonceValidatorInterface|callable(string, int|string): bool           $nonceValidator
     */
    public function __construct(
        private Crypto $crypto,
        CredentialsProviderInterface|callable $credentialsProvider,
        private TimeProviderInterface $timeProvider,
        NonceValidatorInterface|callable $nonceValidator,
        private int $timestampSkewSec,
        private int $localtimeOffsetSec,
    ) {
        $this->credentialsProvider = $credentialsProvider instanceof CredentialsProviderInterface
            ? $credentialsProvider
            : new CallbackCredentialsProvider($credentialsProvider);

        $this->nonceValidator = $nonceValidator instanceof NonceValidatorInterface
            ? $nonceValidator
            : new CallbackNonceValidator($nonceValidator);
    }

    public function authenticate(
        string $method,
        string $host,
        int|string $port,
        string $resource,
        ?string $contentType = null,
        ?string $payload = null,
        Header|string|null $headerObjectOrString = null,
    ): Response {
        if (null === $headerObjectOrString) {
            throw new UnauthorizedException('Missing Authorization header');
        }

        $header = HeaderFactory::createFromHeaderObjectOrString(
            'Authorization',
            $headerObjectOrString,
            static function (): never {
                throw new UnauthorizedException('Invalid Authorization header');
            },
        );

        // Czas mierzymy przed jakimkolwiek innym przetwarzaniem.
        $now = $this->timeProvider->createTimestamp() + $this->localtimeOffsetSec;

        // Komplet atrybutów sprawdzamy PRZED złożeniem Artifacts. Oryginał budował je
        // pierwsze, więc czytał pola, o których dopiero za chwilę stwierdzał, że ich nie ma.
        foreach (['id', 'ts', 'nonce', 'mac'] as $requiredAttribute) {
            if (null === $header->attribute($requiredAttribute)) {
                throw new UnauthorizedException('Missing attributes');
            }
        }

        $timestamp = $header->attribute('ts');
        \assert(null !== $timestamp);
        if (1 !== preg_match('/^\d{1,15}$/D', $timestamp)) {
            // Bez tego `abs($ts - $now)` niżej rzucał TypeError na nieliczbowym `ts`,
            // czyli zamieniał odmowę w błąd 500 sterowany przez klienta.
            throw new UnauthorizedException('Invalid timestamp');
        }

        $nonce = $header->attribute('nonce');
        \assert(null !== $nonce);

        $artifacts = new Artifacts(
            $method,
            $host,
            $port,
            $resource,
            $timestamp,
            $nonce,
            $header->attribute('ext'),
            $payload,
            $contentType,
            $header->attribute('hash'),
            $header->attribute('app'),
            $header->attribute('dlg'),
        );

        $credentials = $this->loadCredentials($header->attribute('id'));

        $calculatedMac = $this->crypto->calculateMac('header', $credentials, $artifacts);

        $mac = $header->attribute('mac');
        \assert(null !== $mac);
        if (!hash_equals($calculatedMac, $mac)) {
            throw new UnauthorizedException('Bad MAC');
        }

        if (null !== $artifacts->payload()) {
            $hash = $artifacts->hash();
            if (null === $hash) {
                // Trudno tu dojść z brakującym hashem — MAC i tak by się nie zgodził —
                // ale wołający może podać payload, którego klient nie zahaszował.
                throw new UnauthorizedException('Missing required payload hash');
            }

            $calculatedHash = $this->crypto->calculatePayloadHash(
                $artifacts->payload(),
                $credentials->algorithm(),
                $artifacts->contentType() ?? '',
            );

            if (!hash_equals($calculatedHash, $hash)) {
                throw new UnauthorizedException('Bad payload hash');
            }
        }

        if (!$this->nonceValidator->validateNonce($artifacts->nonce(), $artifacts->timestamp())) {
            throw new UnauthorizedException('Invalid nonce');
        }

        // Skew sprawdzamy PO weryfikacji MAC-a — inaczej odpowiedź „Stale timestamp”
        // niosłaby tsm policzony poświadczeniami, których nadawca nie udowodnił.
        if (abs((int) $timestamp - $now) > $this->timestampSkewSec) {
            $ts = $this->timeProvider->createTimestamp() + $this->localtimeOffsetSec;

            throw new UnauthorizedException('Stale timestamp', [
                'ts' => $ts,
                'tsm' => $this->crypto->calculateTsMac($ts, $credentials),
            ]);
        }

        return new Response($credentials, $artifacts);
    }

    /**
     * @param array{payload?: string, content_type?: string, ext?: string} $options
     */
    public function createHeader(CredentialsInterface $credentials, Artifacts $artifacts, array $options = []): Header
    {
        [$payload, $contentType, $hash] = $this->resolvePayloadOptions($credentials, $options);

        $ext = $options['ext'] ?? null;

        $responseArtifacts = new Artifacts(
            $artifacts->method(),
            $artifacts->host(),
            $artifacts->port(),
            $artifacts->resource(),
            $artifacts->timestamp(),
            $artifacts->nonce(),
            $ext,
            $payload,
            $contentType,
            $hash,
            $artifacts->app(),
            $artifacts->dlg(),
        );

        $attributes = [
            'mac' => $this->crypto->calculateMac('response', $credentials, $responseArtifacts),
        ];

        if (null !== $hash) {
            $attributes['hash'] = $hash;
        }

        if (null !== $ext && '' !== $ext) {
            $attributes['ext'] = $ext;
        }

        return HeaderFactory::create('Server-Authorization', $attributes);
    }

    public function authenticatePayload(
        CredentialsInterface $credentials,
        string $payload,
        string $contentType,
        string $hash,
    ): bool {
        $calculatedHash = $this->crypto->calculatePayloadHash($payload, $credentials->algorithm(), $contentType);

        return hash_equals($calculatedHash, $hash);
    }

    public function authenticateBewit(string $host, int|string $port, string $resource): Response
    {
        // Czas mierzymy przed jakimkolwiek innym przetwarzaniem.
        $now = $this->timeProvider->createTimestamp() + $this->localtimeOffsetSec;

        // Modyfikator D domyka wzorzec na końcu ciągu: bez niego `$` łapie też pozycję
        // przed końcowym „\n”. Klasa znaków to [^&], a nie [^&$] — „$” w klasie jest
        // zwykłym znakiem i w oryginale znalazł się tam przez pomyłkę, ucinając bewit
        // na dolarze zamiast go odrzucić.
        if (1 !== preg_match('/^(\/[^\r\n]*)([?&])bewit=([^&\r\n]*)(?:&([^\r\n]+))?$/D', $resource, $resourceParts)) {
            throw new UnauthorizedException('Malformed resource or does not contain bewit');
        }

        $bewit = $this->decodeBewit($resourceParts[3]);

        $parts = explode('\\', $bewit);
        if (4 !== \count($parts)) {
            // Oryginał robił tu list(...) = explode(...) bez liczenia pól, więc krótszy
            // bewit dawał „Undefined array key” i null-e w zmiennych; dalej szło to
            // w arytmetykę i w strlen(), czyli w warningi zamiast w odmowę.
            throw new UnauthorizedException('Malformed bewit');
        }

        [$id, $exp, $mac, $ext] = $parts;

        if (1 !== preg_match('/^\d{1,15}$/D', $exp)) {
            throw new UnauthorizedException('Malformed bewit expiration');
        }

        if ((int) $exp < $now) {
            throw new UnauthorizedException('Access expired');
        }

        $resource = $resourceParts[1];
        if (isset($resourceParts[4])) {
            $resource .= $resourceParts[2] . $resourceParts[4];
        }

        $artifacts = new Artifacts(
            'GET',
            $host,
            $port,
            $resource,
            $exp,
            '',
            $ext,
        );

        // Bewit zawsze niesie pole id, puste gdy klient żadnego nie miał; providerowi
        // podajemy wtedy null, żeby dostał to samo, co Credentials::id() zwróciło przy
        // podpisywaniu, a nie pusty string udający identyfikator.
        $credentials = $this->loadCredentials('' === $id ? null : $id);

        $calculatedMac = $this->crypto->calculateMac('bewit', $credentials, $artifacts);

        if (!hash_equals($calculatedMac, $mac)) {
            throw new UnauthorizedException('Bad MAC');
        }

        return new Response($credentials, $artifacts);
    }

    /**
     * base64url → base64. Oryginał wołał tu str_replace z pustymi wzorcami ('' => '='),
     * które nie robią nic — pary z kodowania po prostu odwrócono hurtem, zamiast je
     * zamienić stronami. Dopełnienie dokładamy sami, żeby dekodować w trybie ścisłym:
     * bez niego base64_decode() milcząco połyka każdy znak spoza alfabetu i z byle
     * śmiecia produkuje „bewit”.
     */
    private function decodeBewit(string $value): string
    {
        $base64 = strtr($value, '-_', '+/');
        $base64 .= str_repeat('=', (4 - \strlen($base64) % 4) % 4);

        $decoded = base64_decode($base64, true);
        if (false === $decoded) {
            throw new UnauthorizedException('Malformed bewit');
        }

        return $decoded;
    }

    private function loadCredentials(?string $id): CredentialsInterface
    {
        $credentials = $this->credentialsProvider->loadCredentialsById($id);

        if (null === $credentials) {
            // Nieznane id kończyło się wcześniej wywołaniem metody na nullu, czyli
            // błędem krytycznym zamiast odmowy.
            throw new UnauthorizedException('Unknown credentials');
        }

        return $credentials;
    }

    /**
     * @param array{payload?: string, content_type?: string, ext?: string} $options
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
}
