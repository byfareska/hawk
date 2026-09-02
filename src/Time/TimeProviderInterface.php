<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Time;

interface TimeProviderInterface
{
    /**
     * Czas uniksowy w sekundach.
     */
    public function createTimestamp(): int;
}
