<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Client;

use Byfareska\Hawk\Crypto\Artifacts;
use Byfareska\Hawk\Header\Header;

/**
 * Podpisane żądanie: gotowy nagłówek do wysłania i pola, z których policzono MAC —
 * te drugie są potrzebne, żeby później zweryfikować podpis odpowiedzi serwera.
 */
final readonly class Request
{
    public function __construct(
        private Header $header,
        private Artifacts $artifacts,
    ) {
    }

    public function header(): Header
    {
        return $this->header;
    }

    public function artifacts(): Artifacts
    {
        return $this->artifacts;
    }
}
