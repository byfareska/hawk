<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Time;

/**
 * Zegar stojący — do testów i do odtwarzania cudzych podpisów.
 */
final readonly class ConstantTimeProvider implements TimeProviderInterface
{
    public function __construct(
        private int $time,
    ) {
    }

    public function createTimestamp(): int
    {
        return $this->time;
    }
}
