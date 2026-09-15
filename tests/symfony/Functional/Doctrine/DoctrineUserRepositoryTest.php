<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Bundle\Doctrine\TenantSynchronizer;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Domain\Identity\Address;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.4: users found by identifier, by subject and by username within a tenant.
 */
final class DoctrineUserRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aUserComesBackAsItWasSaved(): void
    {
        $users = self::users();
        $user = User::create(Uuid::v7(), self::tenant(), new Subject('alice-subject'), 'alice', self::now(), new EmailAddress('alice@example.com'), true);
        $user->updateProfile(new Profile('Alice Example', 'Alice', 'Example', null, 'ali', 'alice', 'https://example.com/alice', 'https://example.com/alice.png', 'https://alice.example', 'female', '1990-01-31', 'Europe/Paris', 'fr-FR'), self::now());
        $user->changePhoneNumber('+33612345678', true, self::now());
        $user->changeAddress(new Address('1 rue de la Paix, 75002 Paris', '1 rue de la Paix', 'Paris', 'Île-de-France', '75002', 'FR'), self::now());
        $user->disable(self::now()->modify('+1 day'));
        $users->save($user);
        self::reload();

        $found = $users->find($user->id) ?? static::fail('The user was not stored.');

        static::assertNotSame($user, $found);
        static::assertTrue($found->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('alice-subject', (string) $found->subject);
        static::assertSame('alice', $found->username);
        static::assertSame('alice@example.com', (string) $found->email);
        static::assertTrue($found->emailVerified);
        static::assertEquals($user->profile, $found->profile);
        static::assertSame('+33612345678', $found->phoneNumber);
        static::assertTrue($found->phoneNumberVerified);
        static::assertEquals($user->address, $found->address);
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now()->modify('+1 day'), $found->updatedAt);
        static::assertEquals(self::now()->modify('+1 day'), $found->disabledAt);
        static::assertFalse($found->isEnabled());
    }

    #[Test]
    public function anEmptyProfileAndNoAddressComeBackAsSuch(): void
    {
        $users = self::users();
        $user = self::user();
        self::reload();

        $found = $users->find($user->id) ?? static::fail('The user was not stored.');

        static::assertNull($found->email);
        static::assertFalse($found->emailVerified);
        static::assertEquals(Profile::empty(), $found->profile);
        static::assertNull($found->address);
        static::assertNull($found->phoneNumber);
        static::assertNull($found->disabledAt);
        static::assertTrue($found->isEnabled());
    }

    #[Test]
    public function aChangeIsWrittenOnSave(): void
    {
        $users = self::users();
        $user = self::user();
        $user->rename('alice2', self::now()->modify('+1 hour'));
        $user->changeEmail(new EmailAddress('alice2@example.com'), false, self::now()->modify('+1 hour'));
        $users->save($user);
        self::reload();

        $found = $users->find($user->id) ?? static::fail('The user was not stored.');

        static::assertSame('alice2', $found->username);
        static::assertSame('alice2@example.com', (string) $found->email);
        static::assertEquals(self::now()->modify('+1 hour'), $found->updatedAt);
    }

    #[Test]
    public function aUserIsFoundBySubjectAndByUsernameWithinTheTenant(): void
    {
        $users = self::users();
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        $other = new TenantSynchronizer(new TenantFactory('https://other.test', 'other', null, new MockClock(self::now())), self::registry())
            ->synchronize();
        $stranger = User::create(Uuid::v7(), $other, new Subject('alice-subject'), 'alice', self::now());
        $users->save($stranger);
        self::reload();

        static::assertTrue($alice->id->equals($users->findBySubject(self::tenant(), new Subject('alice-subject'))?->id));
        static::assertTrue($bob->id->equals($users->findByUsername(self::tenant(), 'bob')?->id));
        static::assertTrue($stranger->id->equals($users->findByUsername($other, 'alice')?->id));
        static::assertNull($users->findBySubject(self::tenant(), new Subject('carol-subject')));
        static::assertNull($users->findByUsername(self::tenant(), 'carol'));
        static::assertNull($users->findByUsername(self::tenant(), 'ALICE'));
        static::assertNull($users->find(Uuid::v7()));
    }

    private static function users(): UserRepositoryInterface
    {
        return self::service('test.heidi.users', UserRepositoryInterface::class);
    }
}
