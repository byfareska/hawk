<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Tests\Crypto;

use Byfareska\Hawk\Credentials\Credentials;
use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Crypto\Artifacts;
use Byfareska\Hawk\Crypto\Crypto;
use Byfareska\Hawk\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Wektory z dflydev/hawk i z referencyjnej implementacji Hawka.
 *
 * To jest kontrakt formatu na drucie: każda z tych wartości musi wyjść co do bajtu taka
 * sama jak przed forkiem, inaczej adresy podpisane starą biblioteką przestają się
 * weryfikować nową (i odwrotnie).
 */
final class CryptoTest extends TestCase
{
    #[DataProvider('payloadDataProvider')]
    public function testCalculatesPayloadHash(
        string $expectedHash,
        string $payload,
        string $algorithm,
        string $contentType,
    ): void {
        self::assertSame($expectedHash, new Crypto()->calculatePayloadHash($payload, $algorithm, $contentType));
    }

    /**
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function payloadDataProvider(): iterable
    {
        yield 'wektor z dflydev/hawk' => [
            'neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=',
            '{"type":"https://tent.io/types/status/v0#"}',
            'sha256',
            'application/vnd.tent.post.v0+json',
        ];

        yield 'parametry content-type są odcinane' => [
            'neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=',
            '{"type":"https://tent.io/types/status/v0#"}',
            'sha256',
            'application/vnd.tent.post.v0+json; charset=utf-8',
        ];
    }

    #[DataProvider('macDataProvider')]
    public function testCalculatesMac(
        string $expectedMac,
        string $type,
        CredentialsInterface $credentials,
        Artifacts $artifacts,
    ): void {
        self::assertSame($expectedMac, new Crypto()->calculateMac($type, $credentials, $artifacts));
    }

    /**
     * @return iterable<string, array{string, string, CredentialsInterface, Artifacts}>
     */
    public static function macDataProvider(): iterable
    {
        yield 'MAC nagłówka' => [
            'Tv8htkzRCslVuZbGns4lNt6E2T0Wl1zJYZLrUjMf+PM=',
            'header',
            new Credentials('HX9QcbD-r3ItFEnRcAuOSg', 'sha256', 'exqbZWtykFZIh2D7cXi9dA'),
            new Artifacts('POST', 'example.com', 80, '/interesting', 1368996800, '3yuYCD4Z', 'some-app-data'),
        ];

        yield 'MAC bewita' => [
            'sxWC+5bEPJnR2XxL9WA027cf/iqNYFvG/j4rfsvkTPI=',
            'bewit',
            new Credentials('s3cr3t-key-do-testow', 'sha256', 'klient-1'),
            new Artifacts('GET', 'example.test', 443, '/api/files/42?v=2', 1788000000, ''),
        ];
    }

    public function testCalculatesTimestampMac(): void
    {
        $credentials = new Credentials('HX9QcbD-r3ItFEnRcAuOSg', 'sha256', 'exqbZWtykFZIh2D7cXi9dA');

        self::assertSame(
            'SteT4vEzdHSa4wneJOmixJ/L3TQQF0IycNG2aSNWCGU=',
            new Crypto()->calculateTsMac(1788000000, $credentials),
        );
    }

    /**
     * Znacznik czasu wchodzi do MAC-a swoim zapisem tekstowym, więc string „1788000000”
     * i int 1788000000 muszą dać ten sam podpis — serwer dostaje go stringiem z żądania,
     * klient intem z zegara.
     */
    public function testTimestampTypeDoesNotChangeTheMac(): void
    {
        $crypto = new Crypto();
        $credentials = new Credentials('s3cr3t-key-do-testow');

        self::assertSame(
            $crypto->calculateMac('bewit', $credentials, new Artifacts('GET', 'a.test', 443, '/x', 1788000000, '')),
            $crypto->calculateMac('bewit', $credentials, new Artifacts('GET', 'a.test', 443, '/x', '1788000000', '')),
        );
    }

    /**
     * Regresja: oryginał zostawiał w tym miejscu „TODO: escape ext” i wklejał ext do ciągu
     * znormalizowanego surowo. Bez escapowania nowa linia w ext przesuwa granice pól, więc
     * dwa różne żądania dają ten sam MAC — dokładnie to, przed czym MAC ma chronić.
     */
    public function testExtIsEscapedSoItCannotForgeFieldBoundaries(): void
    {
        $crypto = new Crypto();
        $credentials = new Credentials('s3cr3t-key-do-testow');

        $withNewline = $crypto->calculateMac(
            'header',
            $credentials,
            new Artifacts('GET', 'a.test', 443, '/x', 1788000000, 'n0nce', "a\nb"),
        );
        $withLiteral = $crypto->calculateMac(
            'header',
            $credentials,
            new Artifacts('GET', 'a.test', 443, '/x', 1788000000, 'n0nce', 'a\\nb'),
        );

        self::assertNotSame($withNewline, $withLiteral);
    }

    public function testBackslashInExtIsEscaped(): void
    {
        $crypto = new Crypto();
        $credentials = new Credentials('s3cr3t-key-do-testow');

        self::assertNotSame(
            $crypto->calculateMac('header', $credentials, new Artifacts('GET', 'a.test', 443, '/x', 1, 'n', 'a\\\\b')),
            $crypto->calculateMac('header', $credentials, new Artifacts('GET', 'a.test', 443, '/x', 1, 'n', 'a\\b')),
        );
    }

    /**
     * Puste ext nie dokłada niczego do ciągu — to warunek zgodności z dflydev/hawk dla
     * wszystkich podpisów, które ext nie używają (czyli dla bewitów).
     */
    public function testEmptyAndMissingExtProduceTheSameMac(): void
    {
        $crypto = new Crypto();
        $credentials = new Credentials('s3cr3t-key-do-testow');

        self::assertSame(
            $crypto->calculateMac('bewit', $credentials, new Artifacts('GET', 'a.test', 443, '/x', 1788000000, '')),
            $crypto->calculateMac('bewit', $credentials, new Artifacts('GET', 'a.test', 443, '/x', 1788000000, '', '')),
        );
    }

    #[DataProvider('rejectedAlgorithms')]
    public function testRejectsAlgorithmsOutsideTheAllowList(string $algorithm): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Crypto()->calculatePayloadHash('x', $algorithm, 'text/plain');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedAlgorithms(): iterable
    {
        yield 'słaby skrót' => ['md5'];
        yield 'suma kontrolna, nie skrót' => ['crc32b'];
        yield 'nieznana nazwa wywracała hash_hmac ValueError-em' => ['nie-ma-takiego'];
    }

    public function testFixedTimeComparisonRejectsShorterAndLongerValues(): void
    {
        $crypto = new Crypto();

        self::assertTrue($crypto->fixedTimeComparison('abcdef', 'abcdef'));
        self::assertFalse($crypto->fixedTimeComparison('abcdef', 'abcde'));
        self::assertFalse($crypto->fixedTimeComparison('abcdef', 'abcdefg'));
        self::assertFalse($crypto->fixedTimeComparison('abcdef', ''));
    }
}
