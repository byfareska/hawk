<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Header;

final class HeaderParser
{
    /**
     * Jedna para klucz="wartość" z escapowaniem w środku (RFC 9110, quoted-string).
     * Oryginał ciął wartość pola przez explode(', '), więc rozpadał się na każdym
     * atrybucie zawierającym przecinek ze spacją — a `ext` to dowolny tekst od klienta.
     */
    private const string ATTRIBUTE_PATTERN = '/([a-z]+)\s*=\s*"((?:[^"\\\\\r\n]|\\\\.)*)"/';

    /**
     * @param list<string>|null $requiredKeys
     *
     * @return array<string, string>
     */
    public static function parseFieldValue(string $fieldValue, ?array $requiredKeys = null): array
    {
        // Nazwa schematu jest w HTTP nieczuła na wielkość liter (RFC 9110) i musi być
        // oddzielona spacją — bez tego drugiego warunku przechodziło też „Hawkish”.
        if (1 !== preg_match('/^Hawk(?:\s+|$)/i', $fieldValue)) {
            throw new NotHawkAuthorizationException();
        }

        $attributes = [];
        preg_match_all(self::ATTRIBUTE_PATTERN, $fieldValue, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $attributes[$match[1]] = self::unescapeValue($match[2]);
        }

        if (null !== $requiredKeys) {
            $missingKeys = array_values(array_filter(
                $requiredKeys,
                static fn (string $key): bool => !isset($attributes[$key]),
            ));

            if ([] !== $missingKeys) {
                throw new FieldValueParserException(
                    'Field value was missing the following required key(s): ' . implode(', ', $missingKeys),
                );
            }
        }

        return $attributes;
    }

    private static function unescapeValue(string $value): string
    {
        return preg_replace('/\\\\(.)/', '$1', $value) ?? $value;
    }
}
