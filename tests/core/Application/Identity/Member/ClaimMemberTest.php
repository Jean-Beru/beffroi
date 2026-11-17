<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity\Member;

use Beffroi\Core\Application\Identity\Member\ClaimMember;
use Beffroi\Core\Domain\Identity\Claim\Birthdate;
use Beffroi\Core\Domain\Identity\Claim\Nickname;
use Beffroi\Core\Domain\Identity\Claim\PhoneNumber;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.1
 */
final class ClaimMemberTest extends TestCase
{
    #[Test]
    public function aClaimIsSaidAsThePersonWouldSayIt(): void
    {
        // Given
        $alice = Fixtures::user();

        // When
        new ClaimMember(new Nickname())->say($alice, 'Ada', Fixtures::now());

        // Then
        static::assertSame('Ada', $alice->profile->nickname);
    }

    #[Test]
    public function anEmptyTextTakesTheClaimAway(): void
    {
        // Given
        $alice = Fixtures::user();
        $alice->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());

        // When
        new ClaimMember(new Nickname())->say($alice, '  ', Fixtures::now());

        // Then
        static::assertNull($alice->profile->nickname);
    }

    #[Test]
    public function whatIsNotTextIsRefused(): void
    {
        // Given
        $alice = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('"nickname" is a string, or null to take it away.');

        // When
        new ClaimMember(new Nickname())->say($alice, 42, Fixtures::now());
    }

    #[Test]
    public function aValueTheClaimDoesNotHoldIsRefused(): void
    {
        // Given
        $alice = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The birthdate "the first of May" must be a day of the calendar, "YYYY-MM-DD", or a year alone, "YYYY", the year "0000" when it is withheld.');

        // When
        new ClaimMember(new Birthdate())->say($alice, 'the first of May', Fixtures::now());
    }

    #[Test]
    public function theNumberAPersonHoldsSaidAgainKeepsItsVerification(): void
    {
        // Given
        $alice = Fixtures::user();
        $alice->changePhoneNumber('+33 1 23 45 67 89', true, Fixtures::now());

        // When
        new ClaimMember(new PhoneNumber())->say($alice, '+33 1 23 45 67 89', Fixtures::now());

        // Then
        static::assertTrue($alice->phoneNumberVerified);
    }
}
