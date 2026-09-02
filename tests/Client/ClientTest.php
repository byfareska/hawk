<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Tests\Client;

use Byfareska\Hawk\Client\ClientBuilder;
use Byfareska\Hawk\Credentials\Credentials;
use Byfareska\Hawk\Exception\InvalidArgumentException;
use Byfareska\Hawk\Time\ConstantTimeProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    /**
     * Regresja: $parsed['host'] czytane bez sprawdzenia dawało warning i pusty host,
     * czyli podpis, którego żaden serwer nie potwierdzi.
     */
    #[DataProvider('unsignableUris')]
    public function testRefusesUrisItCannotSign(string $uri): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->client()->createBewit(new Credentials('sekret'), $uri, 60);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsignableUris(): iterable
    {
        yield 'ścieżka bez hosta' => ['/img/a.png'];
        yield 'adres bez schematu' => ['example.test/img/a.png'];
        yield 'pusty' => [''];
    }

    /**
     * Regresja: backslash jest separatorem pól bewita, więc w id ani w ext wystąpić nie
     * może. Oryginał sklejał je bez sprawdzenia i po cichu produkował podpis, którego
     * serwer nie umiał rozłożyć na części.
     */
    #[DataProvider('fieldsWithSeparator')]
    public function testRefusesBewitFieldsContainingTheSeparator(?string $id, ?string $ext): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->client()->createBewit(
            new Credentials('sekret', 'sha256', $id),
            'https://example.test/x',
            60,
            null === $ext ? [] : ['ext' => $ext],
        );
    }

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function fieldsWithSeparator(): iterable
    {
        yield 'backslash w id' => ['klient\\1', null];
        yield 'backslash w ext' => [null, 'a\\b'];
    }

    public function testRefusesAPayloadWithoutItsContentType(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->client()->createRequest(
            new Credentials('sekret'),
            'https://example.test/x',
            'POST',
            ['payload' => '{}'],
        );
    }

    public function testUsesLocaltimeOffsetWhenSigning(): void
    {
        $credentials = new Credentials('sekret');

        $base = ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(1000))->build();
        $shifted = ClientBuilder::create()
            ->setTimeProvider(new ConstantTimeProvider(900))
            ->setLocaltimeOffset(100)
            ->build();

        self::assertSame(
            $base->createBewit($credentials, 'https://example.test/x', 60),
            $shifted->createBewit($credentials, 'https://example.test/x', 60),
        );
    }

    private function client(): \Byfareska\Hawk\Client\Client
    {
        return ClientBuilder::create()->setTimeProvider(new ConstantTimeProvider(1787996400))->build();
    }
}
