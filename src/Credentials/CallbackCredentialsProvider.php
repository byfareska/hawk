<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Credentials;

final readonly class CallbackCredentialsProvider implements CredentialsProviderInterface
{
    private \Closure $callback;

    /**
     * @param callable(?string): ?CredentialsInterface $callback
     */
    public function __construct(callable $callback)
    {
        $this->callback = $callback(...);
    }

    public function loadCredentialsById(?string $id): ?CredentialsInterface
    {
        return ($this->callback)($id);
    }
}
