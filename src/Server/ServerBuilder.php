<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Server;

use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Credentials\CredentialsProviderInterface;
use Byfareska\Hawk\Crypto\Crypto;
use Byfareska\Hawk\Nonce\NonceValidatorInterface;
use Byfareska\Hawk\Time\DefaultTimeProviderFactory;
use Byfareska\Hawk\Time\TimeProviderInterface;

final class ServerBuilder
{
    private const int DEFAULT_TIMESTAMP_SKEW_SEC = 60;

    private ?Crypto $crypto = null;
    private ?TimeProviderInterface $timeProvider = null;
    private NonceValidatorInterface|\Closure|null $nonceValidator = null;
    private ?int $timestampSkewSec = null;
    private ?int $localtimeOffsetSec = null;

    /**
     * @param CredentialsProviderInterface|\Closure(?string): ?CredentialsInterface $credentialsProvider
     */
    public function __construct(
        private readonly CredentialsProviderInterface|\Closure $credentialsProvider,
    ) {
    }

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

    /**
     * @param NonceValidatorInterface|callable(string, int|string): bool $nonceValidator
     */
    public function setNonceValidator(NonceValidatorInterface|callable $nonceValidator): self
    {
        $this->nonceValidator = $nonceValidator instanceof NonceValidatorInterface
            ? $nonceValidator
            : $nonceValidator(...);

        return $this;
    }

    /**
     * Zero jest tu wartością sensowną — „nie toleruj żadnego rozjazdu zegarów”. Oryginał
     * używał niżej `?:`, więc zamieniał je z powrotem na 60 i wyłączyć skewu nie dawało się
     * wcale. To samo dotyczy setLocaltimeOffsetSec().
     */
    public function setTimestampSkewSec(?int $timestampSkewSec = null): self
    {
        $this->timestampSkewSec = $timestampSkewSec;

        return $this;
    }

    public function setLocaltimeOffsetSec(?int $localtimeOffsetSec = null): self
    {
        $this->localtimeOffsetSec = $localtimeOffsetSec;

        return $this;
    }

    public function build(): Server
    {
        return new Server(
            $this->crypto ?? new Crypto(),
            $this->credentialsProvider,
            $this->timeProvider ?? DefaultTimeProviderFactory::create(),
            $this->nonceValidator ?? static fn (string $nonce, int|string $timestamp): bool => true,
            $this->timestampSkewSec ?? self::DEFAULT_TIMESTAMP_SKEW_SEC,
            $this->localtimeOffsetSec ?? 0,
        );
    }

    /**
     * @param CredentialsProviderInterface|callable(?string): ?CredentialsInterface $credentialsProvider
     */
    public static function create(CredentialsProviderInterface|callable $credentialsProvider): self
    {
        return new self(
            $credentialsProvider instanceof CredentialsProviderInterface
                ? $credentialsProvider
                : $credentialsProvider(...),
        );
    }
}
