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
 * Bewit — podpis w query stringu. To jedyna ścieżka biblioteki osiągalna z przeglądarki,
 * więc każde zniekształcone wejście musi kończyć się odmową, nigdy błędem PHP.
 */
final class BewitTest extends TestCase
{
    private const string KEY = 's3cr3t-key-do-testow';
    private const int NOW = 1787996400;

    /**
     * Bewity wygenerowane dflydev/hawk PRZED forkiem. Muszą przejść weryfikację tak samo,
     * inaczej wszystkie adresy wydane przed wdrożeniem staną się nieważne.
     *
     * @param array{string, int|string, string} $request host, port, zasób
     */
    #[DataProvider('legacyBewits')]
    public function testAcceptsBewitsIssuedByTheOriginalLibrary(
        string $bewit,
        array $request,
        ?string $credentialId,
    ): void {
        $response = $this->server()->authenticateBewit(
            $request[0],
            $request[1],
            $request[2] . (str_contains($request[2], '?') ? '&' : '?') . 'bewit=' . $bewit,
        );

        self::assertSame($credentialId, $response->credentials()->id());
    }

    /**
     * @return iterable<string, array{string, array{string, int, string}, string|null}>
     */
    public static function legacyBewits(): iterable
    {
        yield 'z identyfikatorem, port jawny, query w zasobie' => [
            'a2xpZW50LTFcMTc4ODAwMDAwMFxzeFdDKzViRVBKblIyWHhMOVdBMDI3Y2YvaXFOWUZ2Ry9qNHJmc3ZrVFBJPVw',
            ['example.test', 443, '/api/files/42?v=2'],
            'klient-1',
        ];

        yield 'bez identyfikatora' => [
            'XDE3ODgwMDAwMDBcc3hXQys1YkVQSm5SMlh4TDlXQTAyN2NmL2lxTllGdkcvajRyZnN2a1RQST1c',
            ['example.test', 443, '/api/files/42?v=2'],
            null,
        ];

        yield 'port domyślny dla http' => [
            'a2xpZW50LTFcMTc4Nzk5NjQ2MFx0NXkrcUg0OTJPL24yQ2FQMnFLR3VIQXN2QWZCVGpDUk4xbG5BZGU5dHE0PVw',
            ['example.test', 80, '/img/a.png'],
            'klient-1',
        ];
    }

    /**
     * Bewit wystawiony nową biblioteką musi wyjść znak w znak taki sam jak stary.
     */
    public function testProducesTheSameBewitAsTheOriginalLibrary(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();

        self::assertSame(
            'a2xpZW50LTFcMTc4ODAwMDAwMFxzeFdDKzViRVBKblIyWHhMOVdBMDI3Y2YvaXFOWUZ2Ry9qNHJmc3ZrVFBJPVw',
            $client->createBewit(
                new Credentials(self::KEY, 'sha256', 'klient-1'),
                'https://example.test/api/files/42?v=2',
                3600,
            ),
        );
    }

    #[DataProvider('roundTrips')]
    public function testRoundTripsWhatItSigns(string $uri, string $host, int $port, string $path): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $bewit = $client->createBewit(new Credentials(self::KEY, 'sha256', 'klient-1'), $uri, 3600);

        $resource = $path . (str_contains($path, '?') ? '&' : '?') . 'bewit=' . $bewit;

        self::assertSame('klient-1', $this->server()->authenticateBewit($host, $port, $resource)->credentials()->id());
    }

    /**
     * @return iterable<string, array{string, string, int, string}>
     */
    public static function roundTrips(): iterable
    {
        yield 'sama ścieżka' => ['https://example.test/img/a.png', 'example.test', 443, '/img/a.png'];
        yield 'ścieżka z query' => ['https://example.test/img?id=7', 'example.test', 443, '/img?id=7'];
        yield 'port niestandardowy' => ['http://example.test:3180/x', 'example.test', 3180, '/x'];
        yield 'znaki zakodowane procentowo' => ['https://example.test/a%20b', 'example.test', 443, '/a%20b'];
    }

    /**
     * Bewit nie musi stać na końcu adresu — parametry za nim zostają w podpisanym zasobie.
     */
    public function testBewitInTheMiddleOfTheQueryString(): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $bewit = $client->createBewit(new Credentials(self::KEY), 'https://example.test/x?a=1&c=2', 3600);

        self::assertSame(
            '/x?a=1&c=2',
            $this->server()->authenticateBewit('example.test', 443, '/x?a=1&bewit=' . $bewit . '&c=2')
                ->artifacts()->resource(),
        );
    }

    #[DataProvider('rejectedResources')]
    public function testRejectsMalformedInputWithAnUnauthorizedException(string $resource, string $message): void
    {
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage($message);

        $this->server()->authenticateBewit('example.test', 443, $resource);
    }

    /**
     * Każdy z tych przypadków dawał w oryginale warning, notice albo błąd typu — czyli 500
     * sterowane treścią żądania — zamiast czystej odmowy.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function rejectedResources(): iterable
    {
        yield 'brak bewita' => ['/x?a=1', 'does not contain bewit'];
        yield 'zasób bez wiodącego ukośnika' => ['x?bewit=abc', 'does not contain bewit'];
        yield 'pusty bewit' => ['/x?bewit=', 'Malformed bewit'];
        yield 'bewit spoza alfabetu base64' => ['/x?bewit=****', 'Malformed bewit'];

        // list() = explode() bez liczenia pól: „Undefined array key 1/2/3”, potem null-e
        // w arytmetyce i w porównaniu MAC-a.
        yield 'za mało pól' => ['/x?bewit=' . self::b64('klient-1\\1788000000'), 'Malformed bewit'];
        yield 'za dużo pól' => ['/x?bewit=' . self::b64('a\\1\\b\\c\\d'), 'Malformed bewit'];

        // „abc” < int w PHP 8 to porównanie tekstowe, więc test wygaśnięcia przepuszczał
        // taką wartość i szedł dalej z nieliczbowym exp.
        yield 'nieliczbowe wygaśnięcie' => ['/x?bewit=' . self::b64('a\\abc\\mac\\'), 'Malformed bewit expiration'];
        yield 'ujemne wygaśnięcie' => ['/x?bewit=' . self::b64('a\\-1\\mac\\'), 'Malformed bewit expiration'];

        yield 'podpis wygasł' => ['/x?bewit=' . self::b64('a\\1\\mac\\'), 'Access expired'];
        yield 'zły MAC' => ['/x?bewit=' . self::b64('a\\9999999999\\zlyMac\\'), 'Bad MAC'];
    }

    /**
     * Regresja: klasa znaków w oryginalnym wyrażeniu to [^&$] — „$” trafiło tam przez
     * pomyłkę (w klasie jest zwykłym znakiem, nie kotwicą), więc bewit urywał się na
     * dolarze i szedł do dekodowania obcięty.
     */
    public function testDollarSignInBewitIsRejectedInsteadOfTruncatingIt(): void
    {
        $this->expectException(UnauthorizedException::class);

        $this->server()->authenticateBewit('example.test', 443, '/x?bewit=' . self::b64('a\\9999999999\\m\\') . '$evil');
    }

    public function testUnknownCredentialIdIsRefusedInsteadOfCrashing(): void
    {
        $server = ServerBuilder::create(static fn (?string $id): ?CredentialsInterface => null)
            ->setTimeProvider(new ConstantTimeProvider(self::NOW))
            ->build();

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Unknown credentials');

        $server->authenticateBewit('example.test', 443, '/x?bewit=' . self::b64('nieznane\\9999999999\\m\\'));
    }

    /**
     * Bewit z innego hosta, portu albo zasobu nie może przejść — to cała treść podpisu.
     */
    #[DataProvider('mismatchedRequests')]
    public function testRefusesBewitReplayedAgainstAnotherTarget(string $host, int $port, string $path): void
    {
        $client = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(self::NOW))->build();
        $bewit = $client->createBewit(new Credentials(self::KEY), 'https://example.test/img/a.png', 3600);

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Bad MAC');

        $this->server()->authenticateBewit($host, $port, $path . '?bewit=' . $bewit);
    }

    /**
     * @return iterable<string, array{string, int, string}>
     */
    public static function mismatchedRequests(): iterable
    {
        yield 'inny host' => ['evil.test', 443, '/img/a.png'];
        yield 'inny port' => ['example.test', 8443, '/img/a.png'];
        yield 'inna ścieżka' => ['example.test', 443, '/img/b.png'];
        yield 'doklejony parametr' => ['example.test', 443, '/img/a.png?admin=1'];
    }

    private function server(): Server
    {
        return ServerBuilder::create(static fn (?string $id): CredentialsInterface => new Credentials(
            self::KEY,
            'sha256',
            $id,
        ))
            ->setTimeProvider(new ConstantTimeProvider(self::NOW))
            ->build();
    }

    private static function b64(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
