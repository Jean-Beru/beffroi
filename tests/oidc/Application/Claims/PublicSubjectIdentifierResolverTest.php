<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\TestCase;

final class PublicSubjectIdentifierResolverTest extends TestCase
{
    /**
     * OIDC Core §8
     */
    #[Test]
    public function itGivesEveryClientTheSubjectOfTheUser(): void
    {
        // Given
        $user = Fixtures::user();
        $resolver = Subjects::publicKind();

        // When / Then
        static::assertSame($user->subject, $resolver->resolve($user, Clients::public($user->tenant)));
        static::assertSame($user->subject, $resolver->resolve($user, Clients::public($user->tenant, 'other')));
    }

    #[Test]
    public function itReadsBackTheSubjectTheCoreKeeps(): void
    {
        // Given
        $user = Fixtures::user();
        $users = new InMemoryUserRepository();
        $users->save($user);
        $resolver = Subjects::publicKind($users);

        // When
        $found = $resolver->findUser(Clients::public($user->tenant), $user->subject);

        // Then
        static::assertSame($user, $found);
    }

    #[Test]
    public function aSubjectThatBelongsToNobodyNamesNobody(): void
    {
        // Given
        $resolver = Subjects::publicKind();

        // When
        $found = $resolver->findUser(Clients::public(Fixtures::tenant()), new Subject('a-value-nobody-was-handed'));

        // Then
        static::assertNull($found);
    }

    #[Test]
    public function itAsksNothingOfARegistration(): void
    {
        // Given
        $service = Clients::service(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When
        Subjects::publicKind()->assertAssignable($service->registration);

        // Then
        static::assertNull($service->registration->subjectType);
    }
}
