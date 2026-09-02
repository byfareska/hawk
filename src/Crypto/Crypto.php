<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Crypto;

use Byfareska\Hawk\Credentials\CredentialsInterface;
use Byfareska\Hawk\Exception\InvalidArgumentException;

/**
 * Znormalizowane ciągi Hawka i liczone z nich MAC-i.
 *
 * Kształt każdego ciągu jest częścią protokołu, nie szczegółem implementacji: zmiana
 * jednego bajtu unieważnia wszystkie wystawione wcześniej podpisy. Wektory z
 * referencyjnej implementacji siedzą w CryptoTest i pilnują, żeby tak się nie stało.
 */
final class Crypto
{
    public const int HEADER_VERSION = 1;

    /**
     * Algorytmy MAC-a dopuszczone przez spec Hawka.
     *
     * Lista jest zamknięta świadomie. hash_hmac() rzuca ValueError na nieznanej nazwie,
     * więc bez niej algorytm wzięty skądkolwiek z zewnątrz wywracał proces zamiast dać
     * czytelny błąd — a nazwy w rodzaju „md5” czy „crc32b” przechodziłyby bez słowa.
     *
     * @var list<string>
     */
    public const array ALGORITHMS = ['sha256', 'sha512'];

    public function calculatePayloadHash(string $payload, string $algorithm, string $contentType): string
    {
        self::assertAlgorithm($algorithm);

        [$contentType] = explode(';', $contentType);
        $contentType = strtolower(trim($contentType));

        $normalized = 'hawk.' . self::HEADER_VERSION . '.payload' . "\n" .
            $contentType . "\n" .
            $payload . "\n";

        return base64_encode(hash($algorithm, $normalized, true));
    }

    public function calculateMac(string $type, CredentialsInterface $credentials, Artifacts $attributes): string
    {
        $algorithm = $credentials->algorithm();
        self::assertAlgorithm($algorithm);

        $normalized = $this->generateNormalizedString($type, $attributes);

        return base64_encode(hash_hmac($algorithm, $normalized, $credentials->key(), true));
    }

    public function calculateTsMac(int|string $ts, CredentialsInterface $credentials): string
    {
        $algorithm = $credentials->algorithm();
        self::assertAlgorithm($algorithm);

        $normalized = 'hawk.' . self::HEADER_VERSION . '.ts' . "\n" .
            $ts . "\n";

        return base64_encode(hash_hmac($algorithm, $normalized, $credentials->key(), true));
    }

    /**
     * Porównanie MAC-ów odporne na pomiar czasu.
     *
     * Zostaje w publicznym API pod starą nazwą (używały jej implementacje spoza pakietu),
     * ale w środku jest już hash_equals() zamiast ręcznej pętli po znakach: ta była
     * napisana poprawnie, tylko nie ma powodu utrzymywać własnej kryptografii tam, gdzie
     * PHP daje gotową funkcję.
     */
    public function fixedTimeComparison(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }

    /**
     * Ciąg znormalizowany dokładnie tak, jak opisuje go spec Hawka:
     *
     *   hawk.1.<typ>\n<ts>\n<nonce>\n<METODA>\n<zasób>\n<host>\n<port>\n<hash>\n<ext>\n
     *   [<app>\n<dlg>\n]
     */
    private function generateNormalizedString(string $type, Artifacts $attributes): string
    {
        $normalized = 'hawk.' . self::HEADER_VERSION . '.' . $type . "\n" .
            $attributes->timestamp() . "\n" .
            $attributes->nonce() . "\n" .
            strtoupper($attributes->method()) . "\n" .
            $attributes->resource() . "\n" .
            strtolower($attributes->host()) . "\n" .
            $attributes->port() . "\n" .
            ($attributes->hash() ?? '') . "\n";

        $ext = $attributes->ext();
        if (null !== $ext && '' !== $ext) {
            $normalized .= self::escapeExt($ext);
        }

        $normalized .= "\n";

        $app = $attributes->app();
        if (null !== $app && '' !== $app) {
            $normalized .= $app . "\n" .
                ($attributes->dlg() ?? '') . "\n";
        }

        return $normalized;
    }

    /**
     * Jedyne pole ciągu znormalizowanego, którego treść pochodzi od użytkownika, a nie
     * z samego żądania. Bez escapowania backslasha i nowej linii ta sama wartość MAC-a
     * odpowiadałaby różnym zestawom pól (ext „a\nb” nie różni się wtedy od ext „a”
     * z doklejonym „b” w kolejnym polu) — dlatego spec każe je escapować, a oryginał
     * zostawił w tym miejscu „TODO: escape ext”.
     *
     * UWAGA: to jedyna zmiana formatu na drucie względem dflydev/hawk. Dotyczy wyłącznie
     * żądań, które faktycznie używają ext; dla pustego ext ciąg jest bajt w bajt ten sam.
     */
    private static function escapeExt(string $ext): string
    {
        return str_replace(['\\', "\n"], ['\\\\', '\\n'], $ext);
    }

    private static function assertAlgorithm(string $algorithm): void
    {
        if (!\in_array($algorithm, self::ALGORITHMS, true)) {
            throw new InvalidArgumentException(\sprintf(
                'Unsupported Hawk algorithm "%s"; expected one of: %s.',
                $algorithm,
                implode(', ', self::ALGORITHMS),
            ));
        }
    }
}
