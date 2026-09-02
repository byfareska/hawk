<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Nonce;

interface NonceProviderInterface
{
    public function createNonce(): string;
}
