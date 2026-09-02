<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Credentials;

use Byfareska\Hawk\Crypto\Crypto;
use Byfareska\Hawk\Exception\InvalidArgumentException;

/**
 * Para „sekret + identyfikator” pod jeden klucz Hawka.
 *
 * Klucz jest oznaczony #[\SensitiveParameter] i wycięty z __debugInfo(): bez tego
 * pierwszy lepszy wyjątek rzucony niżej w stosie wypisywał go w śladzie stosu, a var_dump
 * na obiekcie poświadczeń pokazywał go wprost. W aplikacji, która karmi tę klasę
 * APP_SECRET-em, to jest sekret całej instalacji.
 */
final readonly class Credentials implements CredentialsInterface
{
    public function __construct(
        #[\SensitiveParameter]
        private string $key,
        private string $algorithm = 'sha256',
        private ?string $id = null,
    ) {
        if (!\in_array($algorithm, Crypto::ALGORITHMS, true)) {
            throw new InvalidArgumentException(\sprintf(
                'Unsupported Hawk algorithm "%s"; expected one of: %s.',
                $algorithm,
                implode(', ', Crypto::ALGORITHMS),
            ));
        }
    }

    public function id(): ?string
    {
        return $this->id;
    }

    public function key(): string
    {
        return $this->key;
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @return array{id: string|null, algorithm: string, key: string}
     */
    public function __debugInfo(): array
    {
        return [
            'id' => $this->id,
            'algorithm' => $this->algorithm,
            'key' => '***',
        ];
    }
}
