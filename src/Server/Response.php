<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Server;

use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Crypto\Artifacts;

/**
 * Wynik udanego uwierzytelnienia: poświadczenia, którymi je potwierdzono, i pola,
 * z których policzono MAC.
 */
final readonly class Response
{
    public function __construct(
        private CredentialsInterface $credentials,
        private Artifacts $artifacts,
    ) {
    }

    public function credentials(): CredentialsInterface
    {
        return $this->credentials;
    }

    public function artifacts(): Artifacts
    {
        return $this->artifacts;
    }
}
