<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Identity;

use Heidi\Core\Application\Identity\UserAlreadyExistsException;
use Heidi\Core\Application\Identity\UserProvisioner;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV4;

final class UserProvisionerTest extends TestCase
{
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
        $this->provisioner = new UserProvisioner($this->users, $this->credentials, $this->hasher, $this->clock);
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
        $this->expectExceptionMessage('A user named "alice" already exists in this tenant.');

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
        $this->expectExceptionMessage('A user with the subject "shared" already exists in this tenant.');

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

    #[Test]
    public function theFirstPasswordCreatesTheCredentialHashedByThePolicyOfTheCore(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $credential = $this->provisioner->setPassword($user, 'correct horse battery staple');

        // Then
        static::assertSame($credential, $this->credentials->findPasswordCredential($user));
        static::assertSame($user, $credential->user);
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertTrue($this->hasher->verify($credential->hash, 'correct horse battery staple'));
        static::assertEquals($this->clock->now(), $credential->createdAt);
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
    }

    #[Test]
    public function theNextPasswordReplacesTheHashOfTheSameCredential(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $first = $this->provisioner->setPassword($user, 'correct horse battery staple');
        $this->clock->modify('+1 day');

        // When
        $second = $this->provisioner->setPassword($user, 'another password');

        // Then
        static::assertSame($first, $second);
        static::assertCount(1, $this->credentials->findByUser($user));
        static::assertTrue($this->hasher->verify($second->hash, 'another password'));
        static::assertFalse($this->hasher->verify($second->hash, 'correct horse battery staple'));
        static::assertEquals($this->clock->now(), $second->hashChangedAt);
        static::assertEquals($this->clock->now()->modify('-1 day'), $second->createdAt);
    }

    /**
     * NIST SP 800-63B §5.1.1.2, counted in characters: eight of them, however many bytes they take.
     */
    #[Test]
    public function aPasswordOfEightMultibyteCharactersIsLongEnough(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $this->provisioner->setPassword($user, 'éééééééé');

        // Then
        static::assertNotNull($this->credentials->findPasswordCredential($user));
    }

    #[Test]
    public function aPasswordOfSevenCharactersIsRefused(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A password is at least 8 characters long.');

        // When
        $this->provisioner->setPassword($user, 'seven77');
    }

    #[Test]
    public function aRefusedPasswordLeavesTheCurrentOneInPlace(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');
        $this->provisioner->setPassword($user, 'éééééééé');

        // When
        try {
            $this->provisioner->setPassword($user, 'seven77');
        } catch (InvalidArgumentException) {
        }

        // Then
        static::assertTrue($this->hasher->verify($this->credentials->findPasswordCredential($user)->hash ?? static::fail('The credential is gone.'), 'éééééééé'));
    }

    #[Test]
    public function aPasswordOf4096BytesIsAccepted(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // When
        $credential = $this->provisioner->setPassword($user, str_repeat('a', UserProvisioner::MAXIMUM_PASSWORD_BYTES));

        // Then
        static::assertSame(4096, UserProvisioner::MAXIMUM_PASSWORD_BYTES);
        static::assertTrue($this->hasher->verify($credential->hash, str_repeat('a', 4096)));
    }

    #[Test]
    public function aPasswordOf4097BytesIsRefused(): void
    {
        // Given
        $user = $this->provisioner->create($this->tenant, 'alice');

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('A password is at most 4096 bytes long.');

        // When
        $this->provisioner->setPassword($user, str_repeat('a', 4097));
    }
}
