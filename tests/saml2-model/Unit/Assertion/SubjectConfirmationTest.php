<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Assertion;

use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-6, M-10, SAML Core §2.4.1.2
 */
final class SubjectConfirmationTest extends TestCase
{
    /**
     * Section 5.3
     */
    #[Test]
    public function itKeepsItsRecipientWindowRequestAndAddress(): void
    {
        // Given
        $notOnOrAfter = new DateTimeImmutable('2026-09-30T12:05:00Z');

        // When
        $confirmation = new SubjectConfirmation(
            'https://sp.example.com/saml/acs',
            $notOnOrAfter,
            '_request',
            '192.0.2.1',
        );

        // Then
        static::assertSame(
            ['https://sp.example.com/saml/acs', $notOnOrAfter, '_request', '192.0.2.1'],
            [
                $confirmation->recipient,
                $confirmation->notOnOrAfter,
                $confirmation->inResponseTo,
                $confirmation->address,
            ],
        );
    }

    /**
     * M-10, SAML Profiles §4.1.5
     */
    #[Test]
    public function itHoldsNeitherRequestNorAddressWhenNoneIsGiven(): void
    {
        // When
        $confirmation = new SubjectConfirmation(
            'https://sp.example.com/saml/acs',
            new DateTimeImmutable('2026-09-30T12:05:00Z'),
            null,
            null,
        );

        // Then
        static::assertSame([null, null], [$confirmation->inResponseTo, $confirmation->address]);
    }

    /**
     * §9.2 row 26, M-6, M-8, M-16
     */
    #[Test]
    public function itRefusesARecipientThatIsNotAUri(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new SubjectConfirmation('/saml/acs', new DateTimeImmutable('2026-09-30T12:05:00Z'), '_request', null);
    }

    /**
     * M-6, M-10
     */
    #[Test]
    public function itRefusesAnInResponseToThatIsNotAnId(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An ID is not an NCName (M-6).');

        // When
        new SubjectConfirmation(
            'https://sp.example.com/saml/acs',
            new DateTimeImmutable('2026-09-30T12:05:00Z'),
            '1-request',
            null,
        );
    }

    /**
     * M-15
     */
    #[Test]
    public function itRefusesAnAddressXmlDoesNotCarry(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The Address holds a character XML does not carry, a NUL among them (M-15).');

        // When
        new SubjectConfirmation(
            'https://sp.example.com/saml/acs',
            new DateTimeImmutable('2026-09-30T12:05:00Z'),
            null,
            "192.0.2.1\u{0}",
        );
    }
}
