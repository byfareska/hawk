<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Client;

use Byfareska\Hawk\Crypto\Crypto;
use Byfareska\Hawk\Nonce\DefaultNonceProviderFactory;
use Byfareska\Hawk\Nonce\NonceProviderInterface;
use Byfareska\Hawk\Time\DefaultTimeProviderFactory;
use Byfareska\Hawk\Time\TimeProviderInterface;

final class ClientBuilder
{
    private ?Crypto $crypto = null;
    private ?TimeProviderInterface $timeProvider = null;
    private ?NonceProviderInterface $nonceProvider = null;
    private ?int $localtimeOffset = null;

    public function setCrypto(Crypto $crypto): self
    {
        $this->crypto = $crypto;

        return $this;
    }

    public function setTimeProvider(TimeProviderInterface $timeProvider): self
    {
        $this->timeProvider = $timeProvider;

        return $this;
    }

    public function setNonceProvider(NonceProviderInterface $nonceProvider): self
    {
        $this->nonceProvider = $nonceProvider;

        return $this;
    }

    public function setLocaltimeOffset(?int $localtimeOffset = null): self
    {
        $this->localtimeOffset = $localtimeOffset;

        return $this;
    }

    public function build(): Client
    {
        return new Client(
            $this->crypto ?? new Crypto(),
            $this->timeProvider ?? DefaultTimeProviderFactory::create(),
            $this->nonceProvider ?? DefaultNonceProviderFactory::create(),
            $this->localtimeOffset ?? 0,
        );
    }

    public static function create(): self
    {
        return new self();
    }
}
