<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Time;

final class DefaultTimeProviderFactory
{
    public static function create(): TimeProviderInterface
    {
        return new TimeProvider();
    }
}
