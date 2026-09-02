<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Nonce;

use Byfareska\Hawk\Exception\InvalidArgumentException;

/**
 * Nonce z random_bytes(), czyli z CSPRNG systemu.
 *
 * Oryginał brał je z ircmaxell/random-lib, i to z getLowStrengthGenerator() — generatora
 * opartego na mt_rand i mikroczasie, wprost opisanego w tamtej bibliotece jako
 * nieprzeznaczony do zastosowań kryptograficznych. Nonce jest jedyną zaporą przed
 * powtórzeniem żądania, więc przewidywalny nonce znosi tę zaporę. Przy okazji znika
 * jedyna zależność pakietu.
 */
final readonly class NonceProvider implements NonceProviderInterface
{
    private const int DEFAULT_LENGTH = 32;

    public function __construct(
        private int $length = self::DEFAULT_LENGTH,
    ) {
        if ($length < 1) {
            throw new InvalidArgumentException('Nonce length must be a positive integer.');
        }
    }

    public function createNonce(): string
    {
        // base64url bez dopełnienia: nonce trafia do nagłówka i do ciągu znormalizowanego,
        // więc nie może zawierać znaków wymagających escapowania. Bajtów bierzemy z zapasem
        // (3 bajty = 4 znaki) i przycinamy do żądanej długości.
        $bytes = random_bytes(max(1, (int) ceil($this->length * 3 / 4)));

        return substr(rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='), 0, $this->length);
    }
}
