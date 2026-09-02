<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Credentials;

interface CredentialsInterface
{
    /**
     * Wspólny sekret, którym liczy się HMAC. Nigdy nie wychodzi na drut.
     */
    public function key(): string;

    /**
     * Jedna z nazw z Crypto::ALGORITHMS.
     */
    public function algorithm(): string;

    /**
     * Publiczny identyfikator poświadczeń — jedyne pole, które klient wysyła jawnie.
     * Może być pusty, gdy serwer i tak zna tylko jeden klucz.
     */
    public function id(): ?string;
}
