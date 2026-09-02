<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Tests\Credentials;

use Byfareska\Hawk\Credentials\Credentials;
use Byfareska\Hawk\Exception\InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class CredentialsTest extends TestCase
{
    public function testRefusesAnAlgorithmOutsideTheAllowList(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Credentials('sekret', 'md5');
    }

    /**
     * Klucz to sekret całej instalacji, a var_dump na poświadczeniach trafia do logów
     * i do stron błędu równie łatwo jak cokolwiek innego.
     */
    public function testDoesNotExposeTheKeyWhenDumped(): void
    {
        $dumped = print_r(new Credentials('bardzo-tajny-sekret', 'sha256', 'klient-1'), true);

        self::assertStringNotContainsString('bardzo-tajny-sekret', $dumped);
        self::assertStringContainsString('klient-1', $dumped);
    }
}
