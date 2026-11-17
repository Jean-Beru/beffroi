<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity\Member;

use Beffroi\Core\Application\Identity\Member\EmailVerifiedMember;
use Beffroi\Core\Application\Identity\Member\MemberInterface;
use Beffroi\Core\Application\Identity\Member\PhoneNumberVerifiedMember;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * OIDC Core §5.1
 */
final class VerifiedMembersTest extends TestCase
{
    /**
     * @return iterable<string, array{MemberInterface}>
     */
    public static function verifications(): iterable
    {
        yield 'the email address' => [new EmailVerifiedMember()];
        yield 'the phone number' => [new PhoneNumberVerifiedMember()];
    }

    #[Test]
    #[DataProvider('verifications')]
    public function aVerificationIsTrueOrFalseAndNothingElse(MemberInterface $member): void
    {
        // Given
        $alice = Fixtures::user();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());
        $alice->changePhoneNumber('+33 1 23 45 67 89', false, Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('"%s" is true or false.', $member->name()));

        // When
        $member->say($alice, 'yes', Fixtures::now());
    }

    #[Test]
    #[DataProvider('verifications')]
    public function aVerificationSaidAsItIsLeavesThePersonUntouched(MemberInterface $member): void
    {
        // Given
        $alice = Fixtures::user();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());
        $alice->changePhoneNumber('+33 1 23 45 67 89', false, Fixtures::now());

        // When
        $member->say($alice, false, new DateTimeImmutable('2026-09-16T10:00:00+00:00'));

        // Then
        static::assertEquals(Fixtures::now(), $alice->updatedAt);
    }

    #[Test]
    #[DataProvider('verifications')]
    public function nothingToVerifyIsWrittenAsNothing(MemberInterface $member): void
    {
        // Given
        $alice = Fixtures::user();

        // When
        $written = $member->of($alice);

        // Then
        static::assertSame([$member->name() => null], $written);
    }

    #[Test]
    #[DataProvider('verifications')]
    public function aVerificationIsWrittenInWords(MemberInterface $member): void
    {
        // Given
        $alice = Fixtures::user();
        $alice->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());
        $alice->changePhoneNumber('+33 1 23 45 67 89', false, Fixtures::now());

        // When
        $member->say($alice, true, Fixtures::now());

        // Then
        static::assertSame([$member->name() => 'true'], $member->of($alice));
    }
}
