<?php

declare(strict_types=1);

namespace Byfareska\Hawk\Tests\Header;

use Byfareska\Hawk\Exception\InvalidArgumentException;
use Byfareska\Hawk\Header\FieldValueParserException;
use Byfareska\Hawk\Header\HeaderFactory;
use Byfareska\Hawk\Header\HeaderParser;
use Byfareska\Hawk\Header\NotHawkAuthorizationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HeaderTest extends TestCase
{
    /**
     * Kształt wartości pola jest kontraktem z każdym klientem Hawka — musi zostać taki,
     * jaki wypisywał dflydev/hawk.
     */
    public function testFieldValueKeepsTheOriginalShape(): void
    {
        self::assertSame(
            'Hawk id="exqbZWtykFZIh2D7cXi9dA", ts="1368996800", nonce="3yuYCD4Z", '
                . 'ext="some-app-data", mac="Tv8htkzRCslVuZbGns4lNt6E2T0Wl1zJYZLrUjMf+PM="',
            HeaderFactory::create('Authorization', [
                'id' => 'exqbZWtykFZIh2D7cXi9dA',
                'ts' => 1368996800,
                'nonce' => '3yuYCD4Z',
                'ext' => 'some-app-data',
                'mac' => 'Tv8htkzRCslVuZbGns4lNt6E2T0Wl1zJYZLrUjMf+PM=',
            ])->fieldValue(),
        );
    }

    /**
     * Regresja: oryginał wklejał wartość między cudzysłowy bez escapowania, więc ext
     * z cudzysłowem zamykał atrybut przedwcześnie i przemycał kolejne pola.
     */
    public function testEscapesQuotesAndBackslashesInValues(): void
    {
        $header = HeaderFactory::create('Authorization', ['ext' => 'a"b\\c']);

        self::assertSame('Hawk ext="a\\"b\\\\c"', $header->fieldValue());
        self::assertSame(
            'a"b\\c',
            HeaderParser::parseFieldValue($header->fieldValue())['ext'],
        );
    }

    /**
     * CR i LF w wartości nagłówka to wstrzyknięcie nagłówka — escapować się ich nie da,
     * więc jedyną poprawną odpowiedzią jest odmowa zbudowania takiego nagłówka.
     */
    #[DataProvider('injectionAttempts')]
    public function testRefusesToBuildAHeaderWithControlCharacters(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        HeaderFactory::create('WWW-Authenticate', ['error' => $value]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function injectionAttempts(): iterable
    {
        yield 'CRLF i podrobiony nagłówek' => ["nope\r\nSet-Cookie: admin=1"];
        yield 'samo LF' => ["nope\nX-Evil: 1"];
        yield 'bajt zerowy' => ["nope\x00"];
    }

    public function testRefusesAttributeNamesThatAreNotHawkAttributes(): void
    {
        $this->expectException(InvalidArgumentException::class);

        HeaderFactory::create('Authorization', ['id"; evil' => 'x']);
    }

    /**
     * Regresja: parser ciął wartość pola przez explode(', '), więc rozpadał się na
     * pierwszym atrybucie zawierającym przecinek ze spacją — a ext to dowolny tekst.
     */
    public function testParsesValuesContainingACommaAndSpace(): void
    {
        $attributes = HeaderParser::parseFieldValue('Hawk id="a", ext="jeden, dwa", mac="m"');

        self::assertSame(['id' => 'a', 'ext' => 'jeden, dwa', 'mac' => 'm'], $attributes);
    }

    /**
     * Regresja: trim($value, '"') zdejmował wszystkie cudzysłowy z brzegów wartości,
     * a nie jedną otaczającą parę.
     */
    public function testKeepsQuotesThatBelongToTheValue(): void
    {
        $value = HeaderFactory::create('Authorization', ['ext' => '"cytat"'])->fieldValue();

        self::assertSame('"cytat"', HeaderParser::parseFieldValue($value)['ext']);
    }

    #[DataProvider('nonHawkFieldValues')]
    public function testRefusesFieldValuesThatAreNotHawk(string $fieldValue): void
    {
        $this->expectException(NotHawkAuthorizationException::class);

        HeaderParser::parseFieldValue($fieldValue);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function nonHawkFieldValues(): iterable
    {
        yield 'inny schemat' => ['Bearer abcdef'];
        // Regresja: strpos(…, 'Hawk') === 0 przepuszczał każdy schemat z tym prefiksem.
        yield 'schemat tylko zaczynający się od Hawk' => ['Hawkish id="a"'];
        yield 'pusta wartość' => [''];
    }

    /**
     * Nazwa schematu jest w HTTP nieczuła na wielkość liter (RFC 9110).
     */
    public function testSchemeIsCaseInsensitive(): void
    {
        self::assertSame(['id' => 'a'], HeaderParser::parseFieldValue('hawk id="a"'));
    }

    public function testReportsMissingRequiredKeys(): void
    {
        $this->expectException(FieldValueParserException::class);
        $this->expectExceptionMessage('nonce, mac');

        HeaderParser::parseFieldValue('Hawk id="a", ts="1"', ['id', 'nonce', 'mac']);
    }
}
