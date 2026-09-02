<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Credentials;

interface CredentialsProviderInterface
{
    /**
     * Poświadczenia dla identyfikatora z żądania albo null, gdy takiego klucza nie ma.
     *
     * null jest tu normalną odpowiedzią, nie błędem — serwer zamienia go na odmowę
     * uwierzytelnienia. Zwrócenie poświadczeń „na wszelki wypadek” zrobiłoby z nieznanego
     * id ważny klucz.
     */
    public function loadCredentialsById(?string $id): ?CredentialsInterface;
}
