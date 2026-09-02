<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Exception;

/**
 * Wspólny nadtyp każdego wyjątku rzucanego przez tę bibliotekę.
 *
 * Bez niego wołający nie ma czego złapać: odmowa uwierzytelnienia, zniekształcony nagłówek
 * i błąd użycia API wychodziły z pakietu jako trzy niepowiązane klasy dziedziczące
 * bezpośrednio po \Exception, więc jedynym pewnym filtrem był catch (\Throwable) — a ten
 * połyka też błędy programisty.
 */
interface HawkException extends \Throwable
{
}
