<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Server;

use Byfareska\Hawk\Exception\HawkException;
use Byfareska\Hawk\Header\Header;
use Byfareska\Hawk\Header\HeaderFactory;

/**
 * Odmowa uwierzytelnienia. To normalny wynik działania serwera, nie awaria — wołający ma
 * z niego zrobić 401 albo 403 i dołożyć nagłówek z getHeader().
 */
final class UnauthorizedException extends \Exception implements HawkException
{
    private ?Header $header = null;

    /** @var array<string, string|int> */
    private array $attributes;

    /**
     * @param array<string, string|int>|null $attributes
     */
    public function __construct(string $message = '', ?array $attributes = null)
    {
        parent::__construct($message);
        $this->attributes = $attributes ?? [];
    }

    public function getHeader(): Header
    {
        if (null !== $this->header) {
            return $this->header;
        }

        $attributes = $this->attributes;
        if ('' !== $this->getMessage()) {
            $attributes['error'] = $this->getMessage();
        }

        return $this->header = HeaderFactory::create('WWW-Authenticate', $attributes);
    }
}
