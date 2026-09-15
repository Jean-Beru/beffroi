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
use function strlen;
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

    /**
     * Decision 0002: a stable "sub", distinct from the technical identifier.
     */
    #[Test]
    public function itCreatesAUserWithAGeneratedSubjectAndNoCredential(): void
    {
        $user = $this->provisioner->create($this->tenant, ' alice ', new EmailAddress('alice@example.com'), true);

        static::assertSame($user, $this->users->find($user->id));
        static::assertSame($this->tenant, $user->tenant);
        static::assertSame('alice', $user->username);
        static::assertSame('alice@example.com', (string) $user->email);
        static::assertTrue($user->emailVerified);
        static::assertInstanceOf(UuidV4::class, Uuid::fromString($user->subject->value));
        static::assertNotSame($user->id->toRfc4122(), $user->subject->value);
        static::assertEquals($this->clock->now(), $user->createdAt);
        static::assertTrue($user->isEnabled());
        static::assertSame([], $this->credentials->findByUser($user));
    }

    #[Test]
    public function itKeepsTheSubjectAnotherProviderGave(): void
    {
        $user = $this->provisioner->create($this->tenant, 'alice', subject: new Subject('f3a1-from-keycloak'));

        static::assertSame('f3a1-from-keycloak', $user->subject->value);
        static::assertSame($user, $this->users->findBySubject($this->tenant, new Subject('f3a1-from-keycloak')));
    }

    #[Test]
    public function twoUsersOfATenantCannotShareAUsername(): void
    {
        $this->provisioner->create($this->tenant, 'alice');

        try {
            $this->provisioner->create($this->tenant, 'alice ');
            static::fail('The second alice was created.');
        } catch (UserAlreadyExistsException $exception) {
            static::assertSame('A user named "alice" already exists in this tenant.', $exception->getMessage());
        }
    }

    #[Test]
    public function twoUsersOfATenantCannotShareASubject(): void
    {
        $this->provisioner->create($this->tenant, 'alice', subject: new Subject('shared'));

        try {
            $this->provisioner->create($this->tenant, 'bob', subject: new Subject('shared'));
            static::fail('Bob was created with the subject of alice.');
        } catch (UserAlreadyExistsException $exception) {
            static::assertSame('A user with the subject "shared" already exists in this tenant.', $exception->getMessage());
        }
        static::assertNull($this->users->findByUsername($this->tenant, 'bob'));
    }

    #[Test]
    public function anotherTenantMayHaveTheSameUsername(): void
    {
        $this->provisioner->create($this->tenant, 'alice');
        $other = $this->provisioner->create(Fixtures::tenant('other', 'https://id.other.example'), 'alice');

        static::assertSame('alice', $other->username);
    }

    #[Test]
    public function theFirstPasswordCreatesTheCredentialHashedByThePolicyOfTheCore(): void
    {
        $user = $this->provisioner->create($this->tenant, 'alice');

        $credential = $this->provisioner->setPassword($user, 'correct horse battery staple');

        static::assertSame($credential, $this->credentials->findPasswordCredential($user));
        static::assertSame($user, $credential->user);
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertTrue($this->hasher->verify($credential->hash, 'correct horse battery staple'));
        static::assertFalse($this->hasher->verify($credential->hash, 'correct horse'));
        static::assertEquals($this->clock->now(), $credential->createdAt);
        static::assertEquals($this->clock->now(), $credential->hashChangedAt);
    }

    #[Test]
    public function theNextPasswordReplacesTheHashOfTheSameCredential(): void
    {
        $user = $this->provisioner->create($this->tenant, 'alice');
        $first = $this->provisioner->setPassword($user, 'correct horse battery staple');
        $this->clock->modify('+1 day');

        $second = $this->provisioner->setPassword($user, 'another password');

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
    public function aPasswordIsAtLeastEightCharactersLong(): void
    {
        $user = $this->provisioner->create($this->tenant, 'alice');

        $this->provisioner->setPassword($user, 'ééééééééé');
        static::assertNotNull($this->credentials->findPasswordCredential($user));

        try {
            $this->provisioner->setPassword($user, 'seven77');
            static::fail('A seven-character password was accepted.');
        } catch (InvalidArgumentException $exception) {
            static::assertSame('A password is at least 8 characters long.', $exception->getMessage());
        }
        static::assertTrue($this->hasher->verify($this->credentials->findPasswordCredential($user)->hash ?? static::fail('The credential is gone.'), 'ééééééééé'));
    }

    #[Test]
    public function aPasswordIsAtMost4096BytesLong(): void
    {
        $user = $this->provisioner->create($this->tenant, 'alice');
        $longest = str_repeat('a', UserProvisioner::MAXIMUM_PASSWORD_BYTES);
        static::assertSame(4096, strlen($longest));

        $this->provisioner->setPassword($user, $longest);

        try {
            $this->provisioner->setPassword($user, $longest . 'a');
            static::fail('A password of 4097 bytes was accepted.');
        } catch (InvalidArgumentException $exception) {
            static::assertSame('A password is at most 4096 bytes long.', $exception->getMessage());
        }
    }
}
