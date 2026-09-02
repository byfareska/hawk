<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Server;

use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Crypto\Artifacts;
use Byfareska\Hawk\Header\Header;

interface ServerInterface
{
    /**
     * @throws UnauthorizedException gdy żądanie nie niesie poprawnego podpisu
     */
    public function authenticate(
        string $method,
        string $host,
        int|string $port,
        string $resource,
        ?string $contentType = null,
        ?string $payload = null,
        Header|string|null $headerObjectOrString = null,
    ): Response;

    /**
     * Weryfikacja bewita — podpisu doklejonego do adresu w parametrze `bewit`.
     *
     * Była dotąd tylko na klasie Server, mimo że to jedyna metoda tego interfejsu używana
     * przez podpisane adresy; wołający programujący pod interfejs jej nie widział.
     *
     * @throws UnauthorizedException
     */
    public function authenticateBewit(string $host, int|string $port, string $resource): Response;

    /**
     * @param array{payload?: string, content_type?: string, ext?: string} $options
     */
    public function createHeader(CredentialsInterface $credentials, Artifacts $artifacts, array $options = []): Header;

    public function authenticatePayload(
        CredentialsInterface $credentials,
        string $payload,
        string $contentType,
        string $hash,
    ): bool;
}
