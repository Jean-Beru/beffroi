<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\InMemory;

use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryRepositoriesTest extends TestCase
{
    #[Test]
    public function usersAreFoundByIdSubjectOrUsernameWithinTheirTenant(): void
    {
        $tenant = Fixtures::tenant();
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $alice = Fixtures::user($tenant, 'alice', 'alice-subject');
        $repository = new InMemoryUserRepository();
        $repository->save($alice);
        $repository->save(Fixtures::user($other, 'alice', 'alice-subject'));

        static::assertSame($alice, $repository->find($alice->id));
        static::assertSame($alice, $repository->findBySubject($tenant, new Subject('alice-subject')));
        static::assertSame($alice, $repository->findByUsername($tenant, 'alice'));
        static::assertNotSame($alice, $repository->findByUsername($other, 'alice'));
        static::assertNull($repository->find(Uuid::v7()));
        static::assertNull($repository->findByUsername($tenant, 'bob'));

        $repository->save(Fixtures::user($other, 'bob', 'bob-subject'));
        static::assertNull($repository->findBySubject($tenant, new Subject('bob-subject')));
        static::assertNull($repository->findByUsername($tenant, 'bob'));
    }

    #[Test]
    public function credentialsAreFoundByUserAndThePasswordOneByKind(): void
    {
        $alice = Fixtures::user();
        $repository = new InMemoryCredentialRepository();
        static::assertNull($repository->findPasswordCredential($alice));

        $password = new PasswordCredential(Uuid::v7(), $alice, new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$x'), Fixtures::now());
        $repository->save($password);
        $repository->save(new PasswordCredential(Uuid::v7(), Fixtures::user(username: 'bob', subject: 'bob-subject'), new PasswordHash(PasswordAlgorithm::Argon2id, '$argon2id$y'), Fixtures::now()));

        static::assertSame($password, $repository->findPasswordCredential($alice));
        static::assertCount(1, $repository->findByUser($alice));

        $repository->save(new PasswordCredential(Uuid::v7(), $alice, new PasswordHash(PasswordAlgorithm::Bcrypt, '$2y$z'), Fixtures::now()));
        static::assertCount(2, $repository->findByUser($alice));
    }
}
