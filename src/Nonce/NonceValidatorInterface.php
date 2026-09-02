<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Nonce;

interface NonceValidatorInterface
{
    /**
     * false, gdy para (nonce, znacznik czasu) już się pojawiła — czyli gdy żądanie jest
     * powtórką. Bewity z definicji nonce'a nie mają i tej ścieżki nie dotykają.
     */
    public function validateNonce(string $nonce, int|string $timestamp): bool;
}
