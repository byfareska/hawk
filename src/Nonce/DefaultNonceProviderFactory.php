<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Nonce;

final class DefaultNonceProviderFactory
{
    public static function create(): NonceProviderInterface
    {
        return new NonceProvider();
    }
}
