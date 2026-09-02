<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Crypto;

/**
 * Komplet pól, z których liczy się MAC pojedynczego żądania — jedno miejsce, w którym
 * klient i serwer muszą się zgadzać co do znaku.
 *
 * `timestamp` zostaje int|string, bo po stronie serwera przychodzi surowym stringiem
 * z nagłówka albo z bewita, a MAC liczy się z jego zapisu tekstowego: rzutowanie na int
 * po cichu zmieniłoby „007” w „7” i unieważniło poprawny podpis.
 */
final readonly class Artifacts
{
    public function __construct(
        private string $method,
        private string $host,
        private int|string $port,
        private string $resource,
        private int|string $timestamp,
        private string $nonce,
        private ?string $ext = null,
        private ?string $payload = null,
        private ?string $contentType = null,
        private ?string $hash = null,
        private ?string $app = null,
        private ?string $dlg = null,
    ) {
    }

    public function timestamp(): int|string
    {
        return $this->timestamp;
    }

    public function nonce(): string
    {
        return $this->nonce;
    }

    public function ext(): ?string
    {
        return $this->ext;
    }

    public function payload(): ?string
    {
        return $this->payload;
    }

    public function contentType(): ?string
    {
        return $this->contentType;
    }

    public function hash(): ?string
    {
        return $this->hash;
    }

    public function app(): ?string
    {
        return $this->app;
    }

    public function dlg(): ?string
    {
        return $this->dlg;
    }

    public function resource(): string
    {
        return $this->resource;
    }

    public function host(): string
    {
        return $this->host;
    }

    public function port(): int|string
    {
        return $this->port;
    }

    public function method(): string
    {
        return $this->method;
    }
}
