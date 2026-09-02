<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Client;

use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Header\Header;

interface ClientInterface
{
    /**
     * @param array{timestamp?: int, nonce?: string, payload?: string, content_type?: string, ext?: string, app?: string, dlg?: string} $options
     */
    public function createRequest(
        CredentialsInterface $credentials,
        string $uri,
        string $method,
        array $options = [],
    ): Request;

    /**
     * Podpis adresu doklejany do query stringa jako `bewit` — jedyny wariant Hawka, który
     * przechodzi przez zwykły odnośnik w przeglądarce.
     *
     * @param array{timestamp?: int, ext?: string} $options
     */
    public function createBewit(
        CredentialsInterface $credentials,
        string $uri,
        int $ttlSec,
        array $options = [],
    ): string;

    /**
     * @param array{payload?: string, content_type?: string} $options
     */
    public function authenticate(
        CredentialsInterface $credentials,
        Request $request,
        Header|string $headerObjectOrString,
        array $options = [],
    ): bool;
}
