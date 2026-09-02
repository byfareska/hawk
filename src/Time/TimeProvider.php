<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Time;

final readonly class TimeProvider implements TimeProviderInterface
{
    public function createTimestamp(): int
    {
        return time();
    }
}
