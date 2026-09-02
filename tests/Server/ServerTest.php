<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Tests\Server;

use Byfareska\Hawk\Client\ClientBuilder;
use Byfareska\Hawk\Credentials\Credentials;
use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Server\Server;
use Byfareska\Hawk\Server\ServerBuilder;
use Byfareska\Hawk\Server\UnauthorizedException;
use Byfareska\Hawk\Time\ConstantTimeProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Uwierzytelnianie nagłówkiem Authorization.
 */
final class ServerTest extends TestCase
{
    private const string KEY = 'HX9QcbD-r3ItFEnRcAuOSg';
    private const string ID = 'exqbZWtykFZIh2D7cXi9dA';
    private const int NOW = 1368996800;

    public function testAuthenticatesAHeaderProducedByTheClient(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $request = $client->createRequest($this->credentials(), 'http://example.com/interesting', 'POST');

        $response = $this->server()->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            headerObjectOrString: $request->header()->fieldValue(),
        );

        self::assertSame(self::ID, $response->credentials()->id());
    }

    /**
     * Nagłówek wygenerowany dflydev/hawk przed forkiem.
     */
    public function testAuthenticatesAHeaderIssuedByTheOriginalLibrary(): void
    {
        $header = 'Hawk id="exqbZWtykFZIh2D7cXi9dA", ts="1368996800", nonce="3yuYCD4Z", '
            . 'ext="some-app-data", mac="Tv8htkzRCslVuZbGns4lNt6E2T0Wl1zJYZLrUjMf+PM="';

        $response = $this->server()->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            headerObjectOrString: $header,
        );

        self::assertSame('some-app-data', $response->artifacts()->ext());
    }

    #[DataProvider('refusedHeaders')]
    public function testRefusesBrokenHeaders(?string $header, string $message): void
    {
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage($message);

        $this->server()->authenticate('POST', 'example.com', 80, '/interesting', headerObjectOrString: $header);
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function refusedHeaders(): iterable
    {
        yield 'brak nagłówka' => [null, 'Missing Authorization header'];
        yield 'komplet pól niepełny' => ['Hawk id="a", ts="1368996800"', 'Missing attributes'];

        // Regresja: `abs($ts - $now)` na nieliczbowym `ts` to TypeError, czyli 500 zamiast
        // odmowy — i to sterowane treścią nagłówka.
        yield 'nieliczbowy ts' => [
            'Hawk id="a", ts="jutro", nonce="n", mac="m"',
            'Invalid timestamp',
        ];
        yield 'ts z wiodącym plusem' => [
            'Hawk id="a", ts="+1368996800", nonce="n", mac="m"',
            'Invalid timestamp',
        ];

        yield 'zły MAC' => [
            'Hawk id="a", ts="1368996800", nonce="n", mac="nie-ten-mac"',
            'Bad MAC',
        ];
    }

    public function testRefusesAHeaderThatIsNotHawk(): void
    {
        $this->expectException(\Byfareska\Hawk\Header\NotHawkAuthorizationException::class);

        $this->server()->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            headerObjectOrString: 'Bearer abcdef',
        );
    }

    public function testStaleTimestampCarriesASignedServerTime(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW - 3600))->build();
        $request = $client->createRequest($this->credentials(), 'http://example.com/interesting', 'POST');

        try {
            $this->server()->authenticate(
                'POST',
                'example.com',
                80,
                '/interesting',
                headerObjectOrString: $request->header()->fieldValue(),
            );
            self::fail('Oczekiwano odmowy na przeterminowanym znaczniku czasu.');
        } catch (UnauthorizedException $e) {
            self::assertSame('Stale timestamp', $e->getMessage());
            self::assertSame((string) self::NOW, $e->getHeader()->attribute('ts'));
            self::assertNotNull($e->getHeader()->attribute('tsm'));
        }
    }

    /**
     * Regresja: `?:` w builderze zamieniał 0 z powrotem na 60, więc „nie toleruj rozjazdu
     * zegarów” nie dało się ustawić.
     */
    public function testZeroSkewIsHonouredInsteadOfFallingBackToTheDefault(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW - 5))->build();
        $request = $client->createRequest($this->credentials(), 'http://example.com/interesting', 'POST');

        $server = ServerBuilder::create($this->credentialsProvider())
            ->setTimeProvider(new ConstantTimeProvider(self::NOW))
            ->setTimestampSkewSec(0)
            ->build();

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Stale timestamp');

        $server->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            headerObjectOrString: $request->header()->fieldValue(),
        );
    }

    public function testVerifiesThePayloadHashWhenAPayloadIsGiven(): void
    {
        $payload = '{"ok":true}';
        $contentType = 'application/json';

        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $request = $client->createRequest($this->credentials(), 'http://example.com/interesting', 'POST', [
            'payload' => $payload,
            'content_type' => $contentType,
        ]);

        $server = $this->server();

        self::assertSame(self::ID, $server->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            $contentType,
            $payload,
            $request->header()->fieldValue(),
        )->credentials()->id());

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Bad payload hash');

        $server->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            $contentType,
            '{"ok":false}',
            $request->header()->fieldValue(),
        );
    }

    public function testNonceValidatorCanRefuseAReplay(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $request = $client->createRequest($this->credentials(), 'http://example.com/interesting', 'POST');

        $server = ServerBuilder::create($this->credentialsProvider())
            ->setTimeProvider(new ConstantTimeProvider(self::NOW))
            ->setNonceValidator(static fn (string $nonce, int|string $timestamp): bool => false)
            ->build();

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Invalid nonce');

        $server->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            headerObjectOrString: $request->header()->fieldValue(),
        );
    }

    public function testSignsItsOwnResponse(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $request = $client->createRequest($this->credentials(), 'http://example.com/interesting', 'POST');

        $response = $this->server()->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            headerObjectOrString: $request->header()->fieldValue(),
        );

        $serverHeader = $this->server()->createHeader($response->credentials(), $response->artifacts());

        self::assertTrue($client->authenticate($this->credentials(), $request, $serverHeader->fieldValue()));
    }

    public function testRefusesAResponseSignedWithAnotherKey(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $request = $client->createRequest($this->credentials(), 'http://example.com/interesting', 'POST');

        $response = $this->server()->authenticate(
            'POST',
            'example.com',
            80,
            '/interesting',
            headerObjectOrString: $request->header()->fieldValue(),
        );

        $forged = $this->server()->createHeader(new Credentials('inny-klucz', 'sha256', self::ID), $response->artifacts());

        self::assertFalse($client->authenticate($this->credentials(), $request, $forged->fieldValue()));
    }

    private function credentials(): CredentialsInterface
    {
        return new Credentials(self::KEY, 'sha256', self::ID);
    }

    /**
     * @return callable(?string): CredentialsInterface
     */
    private function credentialsProvider(): callable
    {
        return static fn (?string $id): CredentialsInterface => new Credentials(self::KEY, 'sha256', $id);
    }

    private function server(): Server
    {
        return ServerBuilder::create($this->credentialsProvider())
            ->setTimeProvider(new ConstantTimeProvider(self::NOW))
            ->build();
    }
}
