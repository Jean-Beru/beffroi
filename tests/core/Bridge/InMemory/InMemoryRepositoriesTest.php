<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\InMemory;

use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryRepositoriesTest extends TestCase
{
    private Tenant $tenant;

    private Tenant $other;

    private User $alice;

    private InMemoryUserRepository $users;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->other = Fixtures::tenant('other', 'https://id.other.example');
        $this->alice = Fixtures::user($this->tenant, 'alice', 'alice-subject');
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
        $this->users->save(Fixtures::user($this->other, 'alice', 'alice-subject'));
        $this->users->save(Fixtures::user($this->other, 'bob', 'bob-subject'));
    }

    #[Test]
    public function aUserIsFoundById(): void
    {
        // When / Then
        static::assertSame($this->alice, $this->users->find($this->alice->id));
    }

    #[Test]
    public function noUserIsFoundForAnUnknownId(): void
    {
        // When / Then
        static::assertNull($this->users->find(Uuid::v7()));
    }

    #[Test]
    public function aUserIsFoundBySubjectWithinItsTenant(): void
    {
        // When / Then
        static::assertSame($this->alice, $this->users->findBySubject($this->tenant, new Subject('alice-subject')));
    }

    #[Test]
    public function aSubjectOfAnotherTenantIsNotFound(): void
    {
        // When / Then
        static::assertNull($this->users->findBySubject($this->tenant, new Subject('bob-subject')));
    }

    #[Test]
    public function aUserIsFoundByUsernameWithinItsTenant(): void
    {
        // When / Then
        static::assertSame($this->alice, $this->users->findByUsername($this->tenant, 'alice'));
        static::assertNotSame($this->alice, $this->users->findByUsername($this->other, 'alice'));
    }

    #[Test]
    public function aUsernameOfAnotherTenantIsNotFound(): void
    {
        // When / Then
        static::assertNull($this->users->findByUsername($this->tenant, 'bob'));
    }

    #[Test]
    public function aUserWithoutCredentialHasNoPasswordCredential(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();

        // When / Then
        static::assertNull($repository->findPasswordCredential($this->alice));
    }

    #[Test]
    public function thePasswordCredentialOfAUserIsFoundAmongThoseOfOtherUsers(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $password = new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$x'), Fixtures::now());
        $repository->save($password);
        $repository->save(new PasswordCredential(Uuid::v7(), Fixtures::user(username: 'bob', subject: 'bob-subject'), new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$y'), Fixtures::now()));

        // When / Then
        static::assertSame($password, $repository->findPasswordCredential($this->alice));
    }

    #[Test]
    public function theCredentialsOfAUserAreListedWithoutThoseOfOtherUsers(): void
    {
        // Given
        $repository = new InMemoryCredentialRepository();
        $repository->save(new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$x'), Fixtures::now()));
        $repository->save(new PasswordCredential(Uuid::v7(), $this->alice, new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$z'), Fixtures::now()));
        $repository->save(new PasswordCredential(Uuid::v7(), Fixtures::user(username: 'bob', subject: 'bob-subject'), new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$y'), Fixtures::now()));

        // When / Then
        static::assertCount(2, $repository->findByUser($this->alice));
    }
}
