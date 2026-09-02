<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Header;

use Byfareska\Hawk\Exception\HawkException;

final class NotHawkAuthorizationException extends \Exception implements HawkException
{
    public function __construct()
    {
        parent::__construct('Field value does not start with Hawk');
    }
}
