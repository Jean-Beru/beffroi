<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordRefusal;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\PasswordRefusedException;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV4;

final class UserProvisionerTest extends TestCase
{
    /**
     * A password past every rule of the value object, and one a list counts: what this suite poses.
     */
    private const string A_PASSWORD = 'correct horse battery staple';

    private const string ANOTHER_PASSWORD = 'nine lives of a quiet cat';

    private const string BREACHED = 'monkey business as usual';

    private Tenant $tenant;

    private InMemoryUserRepository $users;

    private InMemoryCredentialRepository $credentials;

    private NativePasswordHasher $hasher;

    private MockClock $clock;

    private UserProvisioner $provisioner;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->users = new InMemoryUserRepository();
        $this->credentials = new InMemoryCredentialRepository();
        $this->hasher = new NativePasswordHasher();
        $this->clock = new MockClock('2026-09-15T12:00:00+00:00');
        $breaches = BreachedPasswordsOfARecord::holding([self::BREACHED]);
        $this->provisioner = $this->provisionerAsking($breaches);
    }

    #[Test]
    public function itCreatesAnEnabledUserOfTheTenantAndSavesIt(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, ' alice ', new EmailAddress('alice@example.com'), true);

        // Then
        static::assertSame($user, $this->users->find($user->id));
        static::assertSame($this->tenant, $user->tenant);
        static::assertSame('alice', $user->username);
        static::assertSame('alice@example.com', (string) $user->email);
        static::assertTrue($user->emailVerified);
        static::assertEquals($this->clock->now(), $user->createdAt);
        static::assertTrue($user->isEnabled());
    }

    /**
     * Decision 0002: a stable "sub", distinct from the technical identifier.
     */
    #[Test]
    public function itGeneratesARandomSubjectDistinctFromTheIdentifier(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        static::assertInstanceOf(UuidV4::class, Uuid::fromString($user->subject->value));
        static::assertNotSame($user->id->toRfc4122(), $user->subject->value);
    }

    #[Test]
    public function aNewUserHasNoCredential(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        static::assertSame([], $this->credentials->findByUser($user));
    }

    #[Test]
    public function itKeepsTheSubjectAnotherProviderGave(): void
    {
        // When
        $user = $this->provisioner->create($this->tenant, 'alice', subject: new Subject('f3a1-from-keycloak'));

        // Then
        static::assertSame('f3a1-from-keycloak', $user->subject->value);
        static::assertSame($user, $this->users->findBySubject($this->tenant, new Subject('f3a1-from-keycloak')));
    }

    #[Test]
    public function twoUsersOfATenantCannotShareAUsername(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(UserAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A user named "alice" already exists in this tenant.');

        // When
        $this->provisioner->create($this->tenant, 'alice ');
    }

    #[Test]
    public function twoUsersOfATenantCannotShareASubject(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice', subject: new Subject('shared'));

        // Then
        $this->expectException(UserAlreadyExistsException::class);
        $this->expectExceptionMessageIs('A user with the subject "shared" already exists in this tenant.');

        // When
        $this->provisioner->create($this->tenant, 'bob', subject: new Subject('shared'));
    }

    #[Test]
    public function aUserRefusedForItsSubjectIsNotSaved(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice', subject: new Subject('shared'));

        // When
        try {
            $this->provisioner->create($this->tenant, 'bob', subject: new Subject('shared'));
        } catch (UserAlreadyExistsException) {
        }

        // Then
        static::assertNull($this->users->findByUsername($this->tenant, 'bob'));
    }

    #[Test]
    public function anotherTenantMayHaveTheSameUsername(): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'alice');

        // When
        $other = $this->provisioner->create(Fixtures::tenant('other', 'https://id.other.example'), 'alice');

        // Then
        static::assertSame('alice', $other->username);
    }

    /**
     * OIDC Core §5.1: the attributes the "profile", "phone" and "address" scopes stand for, saved at once.
     */
    #[Test]
    public function theProfileThePhoneNumberAndTheAddressAreSetAtOnce(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->clock->modify('+1 day');
        $profile = new Profile('Alice Liddell', 'Alice', 'Liddell', locale: 'en-GB');
        $address = new Address('1 Wonderland Road\nOxford', '1 Wonderland Road', 'Oxford', 'Oxfordshire', 'OX1 1AA', 'GB');

        // When
        $described = $this->provisioner->setProfile($user, $profile, '+44 1865 000000', true, $address);

        // Then
        static::assertSame($user, $described);
        static::assertSame($user, $this->users->find($user->id));
        static::assertSame($profile, $user->profile);
        static::assertSame('+44 1865 000000', $user->phoneNumber);
        static::assertTrue($user->phoneNumberVerified);
        static::assertSame($address, $user->address);
        static::assertEquals($this->clock->now(), $user->updatedAt);
    }

    /**
     * A replacement, not a merge: a second description clears what it does not say.
     */
    #[Test]
    public function aSecondProfileReplacesTheFirstInFull(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->provisioner->setProfile($user, new Profile('Alice Liddell'), '+44 1865 000000', true, new Address(locality: 'Oxford'));

        // When
        $this->provisioner->setProfile($user, new Profile(givenName: 'Alice'));

        // Then
        static::assertNull($user->profile->name);
        static::assertSame('Alice', $user->profile->givenName);
        static::assertNull($user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
        static::assertNull($user->address);
    }

    #[Test]
    public function anEmptyAddressIsNoAddress(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $this->provisioner->setProfile($user, Profile::empty(), address: new Address());

        // Then
        static::assertNull($user->address);
    }

    #[Test]
    public function anAbsentPhoneNumberCannotBeVerified(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An absent phone number cannot be verified.');

        // When
        $this->provisioner->setProfile($user, Profile::empty(), null, true);
    }

    #[Test]
    public function theFirstPasswordCreatesTheCredentialHashedByThePolicyOfTheCore(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $credential = $this->provisioner->setPassword($user, new PlainPassword(self::A_PASSWORD));

        // Then
        static::assertSame($credential, $this->credentials->findByUser($user, PasswordCredential::class)[0]);
        static::assertSame($user, $credential->user);
        static::assertSame(Argon2id::NAME, $credential->hash->algorithm->name());
        static::assertTrue($this->hasher->verify($credential->hash, self::A_PASSWORD));
        static::assertEquals($this->clock->now(), $credential->createdAt);
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
    }

    #[Test]
    public function theNextPasswordReplacesTheHashOfTheSameCredential(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $first = $this->provisioner->setPassword($user, new PlainPassword(self::A_PASSWORD));
        $this->clock->modify('+1 day');

        // When
        $second = $this->provisioner->setPassword($user, new PlainPassword(self::ANOTHER_PASSWORD));

        // Then
        static::assertSame($first, $second);
        static::assertCount(1, $this->credentials->findByUser($user));
        static::assertTrue($this->hasher->verify($second->hash, self::ANOTHER_PASSWORD));
        static::assertFalse($this->hasher->verify($second->hash, self::A_PASSWORD));
        static::assertEquals($this->clock->now(), $second->hashChangedAt);
        static::assertEquals($this->clock->now()->modify('-1 day'), $second->createdAt);
    }

    /**
     * The bounds are the PlainPassword's (tested there); what this one keeps is that a refused password
     * leaves the stored one alone.
     */
    #[Test]
    public function aRefusedPasswordLeavesTheCurrentOneInPlace(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->provisioner->setPassword($user, new PlainPassword(self::A_PASSWORD));

        // When
        try {
            $this->provisioner->setPassword($user, new PlainPassword('seven77'));
        } catch (PasswordRefusedException) {
        }

        // Then
        static::assertTrue($this->hasher->verify(
            $this->credentials->findByUser($user, PasswordCredential::class)[0]->hash ?? static::fail('The credential is gone.'),
            self::A_PASSWORD,
        ));
    }

    /**
     * The rule NIST SP 800-63B §5.1.1.2 puts first, on the path an operator writes a password for
     * somebody: the console gets it by construction and not by remembering it.
     */
    #[Test]
    public function aPasswordAListCountsIsRefused(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        try {
            $this->provisioner->setPassword($user, new PlainPassword(self::BREACHED));
            static::fail('A password a list counts is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::Breached, $exception->refusal);
        }
    }

    #[Test]
    public function aPasswordAListCountsWritesNothing(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        try {
            $this->provisioner->setPassword($user, new PlainPassword(self::BREACHED));
        } catch (PasswordRefusedException) {
        }

        // Then
        static::assertSame([], $this->credentials->findByUser($user, PasswordCredential::class));
    }

    /**
     * Decision 0006: an unknown is not a clean answer. A list that could not be asked refuses the
     * password rather than writing one nobody checked.
     */
    #[Test]
    public function aPasswordNoListCouldBeAskedAboutIsRefused(): void
    {
        // Given
        $provisioner = $this->provisionerAsking(new BreachedPasswordsOfARecord(unreachable: true));
        $user = $provisioner->create($this->tenant, 'alice');

        // When
        try {
            $provisioner->setPassword($user, new PlainPassword(self::A_PASSWORD));
            static::fail('A password nobody could be asked about is refused.');
        } catch (PasswordRefusedException $exception) {
            // Then
            static::assertSame(PasswordRefusal::NotChecked, $exception->refusal);
        }
    }

    /**
     * The answer is written on the credential, so that the first login does not ask again what was just
     * asked.
     */
    #[Test]
    public function aPasswordAListWasAskedAboutIsMarkedAsLookedUp(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $credential = $this->provisioner->setPassword($user, new PlainPassword(self::A_PASSWORD));

        // Then
        static::assertEquals($this->clock->now(), $credential->breachCheckedAt);
        static::assertNull($credential->breachFoundAt);
        static::assertFalse($credential->dueForABreachLookup($this->clock->now()));
    }

    /**
     * A deployment that names no list writes the password and marks nothing: the credential stays due, so
     * the day a list is named it is asked about.
     */
    #[Test]
    public function aDeploymentThatNamesNoListWritesThePasswordAndMarksNothing(): void
    {
        // Given
        $provisioner = $this->provisionerAsking(new BreachedPasswordsOfARecord(looksUp: false));
        $user = $provisioner->create($this->tenant, 'alice');

        // When
        $credential = $provisioner->setPassword($user, new PlainPassword(self::BREACHED));

        // Then
        static::assertNull($credential->breachCheckedAt);
        static::assertTrue($credential->dueForABreachLookup($this->clock->now()));
    }

    /**
     * Issue #327: a tenant that signs its users in by passkey holds no password of anybody, so none is
     * posed, and the list of compromised passwords is not asked about one this provider will not hold.
     */
    #[Test]
    public function aTenantThatAdmitsNoPasswordPosesNone(): void
    {
        // Given
        $carol = Fixtures::user(Fixtures::hardenedTenant());

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('A password proves no login of the tenant "acme", whose logins prove "phishing_resistant" at the least: it is not enrolled here. What it would prove is pwd.');

        // When
        $this->provisioner->setPassword($carol, new PlainPassword('correct horse battery staple'));
    }

    private function provisionerAsking(BreachedPasswordsOfARecord $breaches): UserProvisioner
    {
        return new UserProvisioner(
            $this->users,
            $this->credentials,
            $this->hasher,
            new BreachedPasswordRefusal($breaches),
            new EnrolmentRefusal(),
            new SymfonyUuidGenerator(),
            $this->clock,
        );
    }
}
