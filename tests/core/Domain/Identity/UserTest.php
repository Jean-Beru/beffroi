<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Identity;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Address;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use Symfony\Component\Uid\Uuid;

final class UserTest extends TestCase
{
    #[Test]
    public function aNewUserIsEnabledUnverifiedAndHasAnEmptyProfile(): void
    {
        $user = Fixtures::user();

        static::assertTrue($user->isEnabled());
        static::assertNull($user->email);
        static::assertFalse($user->emailVerified);
        static::assertNull($user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
        static::assertEquals(Profile::empty(), $user->profile);
        static::assertNull($user->address);
        static::assertSame($user->createdAt, $user->updatedAt);
    }

    #[Test]
    public function theUsernameIsTrimmedAndNeverEmpty(): void
    {
        $user = Fixtures::user(username: '  alice  ');
        static::assertSame('alice', $user->username);
        static::assertSame(255, strlen(Fixtures::user(username: str_repeat('a', 255))->username));

        $this->expectException(InvalidArgumentException::class);
        User::create(Uuid::v7(), Fixtures::tenant(), new Subject('s'), '   ', Fixtures::now());
    }

    #[Test]
    public function theUsernameIsAtMost255Characters(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Fixtures::user(username: str_repeat('a', 256));
    }

    #[Test]
    public function itCannotBeCreatedWithAVerifiedButAbsentEmail(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new User(Uuid::v7(), Fixtures::tenant(), new Subject('s'), 'alice', null, true, Profile::empty(), null, false, null, Fixtures::now(), Fixtures::now());
    }

    #[Test]
    public function itCannotBeCreatedWithAVerifiedButAbsentPhoneNumber(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new User(Uuid::v7(), Fixtures::tenant(), new Subject('s'), 'alice', null, false, Profile::empty(), null, true, null, Fixtures::now(), Fixtures::now());
    }

    #[Test]
    public function itCanBeCreatedWithAVerifiedEmailAndAVerifiedPhoneNumber(): void
    {
        $user = new User(Uuid::v7(), Fixtures::tenant(), new Subject('s'), 'alice', new EmailAddress('alice@acme.example'), true, Profile::empty(), '+33600000000', true, null, Fixtures::now(), Fixtures::now());

        static::assertTrue($user->emailVerified);
        static::assertTrue($user->phoneNumberVerified);
    }

    #[Test]
    public function aPhoneNumberCanBeChangedAndVerified(): void
    {
        $user = Fixtures::user();

        $user->changePhoneNumber('+33600000000', true, Fixtures::now());
        static::assertSame('+33600000000', $user->phoneNumber);
        static::assertTrue($user->phoneNumberVerified);

        $user->changePhoneNumber(null, false, Fixtures::now());
        static::assertNull($user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
    }

    /**
     * A verified flag never survives a change of address: a new address is unverified until proven otherwise.
     */
    #[Test]
    public function changingTheEmailCarriesItsOwnVerificationState(): void
    {
        $user = Fixtures::user();
        $later = new DateTimeImmutable('2026-09-16T00:00:00+00:00');

        $user->changeEmail(new EmailAddress('alice@acme.example'), true, $later);
        static::assertTrue($user->emailVerified);
        static::assertSame($later, $user->updatedAt);

        $user->changeEmail(new EmailAddress('alice@other.example'), false, $later);
        static::assertFalse($user->emailVerified);
    }

    #[Test]
    public function anAbsentEmailCannotBeVerified(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Fixtures::user()->changeEmail(null, true, Fixtures::now());
    }

    #[Test]
    public function anAbsentPhoneNumberCannotBeVerified(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Fixtures::user()->changePhoneNumber(null, true, Fixtures::now());
    }

    #[Test]
    public function anEmptyAddressIsStoredAsNoAddress(): void
    {
        $user = Fixtures::user();

        $user->changeAddress(new Address(), Fixtures::now());
        static::assertNull($user->address);

        $user->changeAddress(new Address(locality: 'Lyon'), Fixtures::now());
        static::assertSame('Lyon', $user->address?->locality);

        $user->changeAddress(null, Fixtures::now());
        static::assertNull($user->address);
    }

    #[Test]
    public function disablingIsIdempotentAndReversible(): void
    {
        $user = Fixtures::user();
        $t1 = new DateTimeImmutable('2026-09-16T00:00:00+00:00');
        $t2 = new DateTimeImmutable('2026-09-17T00:00:00+00:00');

        $user->disable($t1);
        $user->disable($t2);
        static::assertFalse($user->isEnabled());
        static::assertSame($t1, $user->disabledAt);
        static::assertSame($t1, $user->updatedAt);

        $user->enable($t2);
        static::assertTrue($user->isEnabled());
        static::assertSame($t2, $user->updatedAt);
    }

    #[Test]
    public function itBelongsToExactlyOneTenant(): void
    {
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);

        static::assertTrue($user->belongsTo($tenant));
        static::assertFalse($user->belongsTo(Fixtures::tenant('other', 'https://id.other.example')));
    }
}
