<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Tests\Nonce;

use Byfareska\Hawk\Exception\InvalidArgumentException;
use Byfareska\Hawk\Nonce\DefaultNonceProviderFactory;
use Byfareska\Hawk\Nonce\NonceProvider;
use PHPUnit\Framework\TestCase;

/**
 * Nonce jest jedyną zaporą przed powtórzeniem żądania. Oryginał brał go domyślnie
 * z getLowStrengthGenerator() biblioteki ircmaxell/random-lib — generatora opartego na
 * mt_rand, wprost tam opisanego jako nieprzeznaczony do kryptografii.
 */
final class NonceProviderTest extends TestCase
{
    public function testProducesUrlSafeNoncesOfTheRequestedLength(): void
    {
        $nonce = new NonceProvider(32)->createNonce();

        self::assertSame(32, \strlen($nonce));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/D', $nonce);
    }

    public function testDoesNotRepeatItself(): void
    {
        $provider = DefaultNonceProviderFactory::create();

        $nonces = array_map(static fn (): string => $provider->createNonce(), range(1, 200));

        self::assertCount(200, array_unique($nonces));
    }

    public function testRefusesANonPositiveLength(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new NonceProvider(0);
    }
}
