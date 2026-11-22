<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use function array_fill;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, section 6.1 step 11, SAML Core §2.7.3.1
 */
final class AttributeTest extends TestCase
{
    /**
     * Section 6.1 step 11
     */
    #[Test]
    public function itKeepsItsNameFormatFriendlyNameAndValues(): void
    {
        // When
        $attribute = new Attribute(
            'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
            AttributeNameFormat::Uri,
            'eduPersonAffiliation',
            [
                'member',
                'student',
            ],
        );

        // Then
        static::assertSame(
            [
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
                AttributeNameFormat::Uri,
                'eduPersonAffiliation',
                ['member', 'student'],
            ],
            [$attribute->name, $attribute->nameFormat, $attribute->friendlyName, $attribute->values],
        );
    }

    /**
     * Section 7, M-15, M-17
     */
    #[Test]
    public function itHoldsTheValuesOfItsBound(): void
    {
        // Given
        $values = array_fill(0, 256, 'member');

        // When
        $attribute = new Attribute('uid', AttributeNameFormat::Unspecified, null, $values);

        // Then
        static::assertSame($values, $attribute->values);
    }

    /**
     * §9.2 row 36, M-15, M-17
     */
    #[Test]
    public function itRefusesValuesOverTheirBound(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('An Attribute holds more than 256 AttributeValue, the bound of section 7 (M-17).');

        // When
        new Attribute('uid', AttributeNameFormat::Unspecified, null, array_fill(0, 257, 'member'));
    }

    /**
     * M-15
     */
    #[Test]
    #[DataProvider('provideTextsNotCarried')]
    public function itRefusesACharacterXmlDoesNotCarry(string $name, ?string $friendlyName, string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An Attribute holds a character XML does not carry, a NUL among them (M-15).');

        // When
        new Attribute($name, AttributeNameFormat::Unspecified, $friendlyName, ['member', $value]);
    }

    /**
     * @return iterable<string, array{string, ?string, string}>
     */
    public static function provideTextsNotCarried(): iterable
    {
        yield 'a NUL in the name' => ["groups\u{0}.other", null, 'admins'];
        yield 'a NUL in the friendly name' => ['groups', "Groups\u{0}", 'admins'];
        yield 'a NUL in a value' => ['groups', 'Groups', "admins\u{0}-of-nothing"];
        yield 'U+FFFE in a value' => ['groups', null, "admins\u{FFFE}"];
    }
}
