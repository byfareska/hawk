<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Nonce;

final readonly class CallbackNonceValidator implements NonceValidatorInterface
{
    private \Closure $callback;

    /**
     * @param callable(string, int|string): bool $callback
     */
    public function __construct(callable $callback)
    {
        $this->callback = $callback(...);
    }

    public function validateNonce(string $nonce, int|string $timestamp): bool
    {
        return (bool) ($this->callback)($nonce, $timestamp);
    }
}
