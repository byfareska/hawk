<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Header;

/**
 * Nagłówek Hawka: nazwa pola, gotowa wartość pola i rozłożone na części atrybuty.
 *
 * Atrybuty trzymamy jako stringi, bo tym są na drucie. Bez tego `ts` bywało raz intem
 * (z klienta), raz stringiem (z parsera), a MAC liczy się z zapisu tekstowego.
 */
final readonly class Header
{
    /** @var array<string, string> */
    private array $attributes;

    /**
     * @param array<string, string|int>|null $attributes
     */
    public function __construct(
        private string $fieldName,
        private string $fieldValue,
        ?array $attributes = null,
    ) {
        $this->attributes = array_map(strval(...), $attributes ?? []);
    }

    public function fieldName(): string
    {
        return $this->fieldName;
    }

    public function fieldValue(): string
    {
        return $this->fieldValue;
    }

    /**
     * @param list<string>|null $keys
     *
     * @return array<string, string>
     */
    public function attributes(?array $keys = null): array
    {
        if (null === $keys) {
            return $this->attributes;
        }

        $attributes = [];
        foreach ($keys as $key) {
            if (isset($this->attributes[$key])) {
                $attributes[$key] = $this->attributes[$key];
            }
        }

        return $attributes;
    }

    public function attribute(string $key): ?string
    {
        return $this->attributes[$key] ?? null;
    }
}
