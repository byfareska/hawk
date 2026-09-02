<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Header;

use Byfareska\Hawk\Exception\InvalidArgumentException;

final class HeaderFactory
{
    /**
     * Nazwy atrybutów Hawka to krótkie słowa z małych liter (id, ts, nonce, mac, ext,
     * hash, app, dlg, error). Cokolwiek innego oznacza, że wołający buduje nagłówek
     * z danych, nad którymi nie panuje.
     */
    private const string KEY_PATTERN = '/^[a-z]+$/D';

    /**
     * @param array<string, string|int>|null $attributes
     */
    public static function create(string $fieldName, ?array $attributes = null): Header
    {
        $fieldValue = 'Hawk';

        if (null !== $attributes) {
            $index = 0;
            foreach ($attributes as $key => $value) {
                if ($index++ > 0) {
                    $fieldValue .= ',';
                }

                $fieldValue .= ' ' . self::assertKey($key) . '="' . self::escapeValue((string) $value) . '"';
            }
        }

        return new Header($fieldName, $fieldValue, $attributes);
    }

    /**
     * @param list<string>|null $requiredKeys
     */
    public static function createFromString(string $fieldName, string $fieldValue, ?array $requiredKeys = null): Header
    {
        return static::create(
            $fieldName,
            HeaderParser::parseFieldValue($fieldValue, $requiredKeys),
        );
    }

    /**
     * @param callable(): void $onError wołane, gdy wejście nie jest ani stringiem, ani nagłówkiem
     */
    public static function createFromHeaderObjectOrString(
        string $fieldName,
        mixed $headerObjectOrString,
        callable $onError,
    ): Header {
        if ($headerObjectOrString instanceof Header) {
            return $headerObjectOrString;
        }

        if (\is_string($headerObjectOrString)) {
            return static::createFromString($fieldName, $headerObjectOrString);
        }

        $onError();

        // Oryginał w tym miejscu zwracał null, więc wołający dostawał TypeError kilka linii
        // dalej zamiast błędu, który sam zgłosił. Jeżeli $onError nie rzuci, rzucamy my.
        throw new InvalidArgumentException(\sprintf(
            'Header must either be a string or an instance of %s.',
            Header::class,
        ));
    }

    /**
     * Wartość atrybutu idzie do nagłówka HTTP w cudzysłowie, więc backslash i cudzysłów
     * muszą zostać escapowane parą znaków (RFC 9110, quoted-pair). CR i LF escapować się
     * nie da — wartość z nimi zakończyłaby nagłówek i zaczęła kolejny, czyli byłaby
     * wstrzyknięciem nagłówka. Oryginał nie robił ani jednego, ani drugiego: wklejał
     * wartość wprost między cudzysłowy.
     */
    private static function escapeValue(string $value): string
    {
        if (1 === preg_match('/[\r\n\x00]/', $value)) {
            throw new InvalidArgumentException(
                'Hawk header attribute value must not contain CR, LF or NUL.',
            );
        }

        return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
    }

    private static function assertKey(string $key): string
    {
        if (1 !== preg_match(self::KEY_PATTERN, $key)) {
            throw new InvalidArgumentException(\sprintf(
                'Hawk header attribute name "%s" must match %s.',
                $key,
                self::KEY_PATTERN,
            ));
        }

        return $key;
    }
}
