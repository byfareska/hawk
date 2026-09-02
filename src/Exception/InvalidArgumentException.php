<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Exception;

/**
 * Błąd użycia API biblioteki (zły algorytm, URI bez hosta, niedozwolony znak w polu bewita)
 * — w odróżnieniu od odmowy uwierzytelnienia, która jest normalnym wynikiem działania.
 */
final class InvalidArgumentException extends \InvalidArgumentException implements HawkException
{
}
