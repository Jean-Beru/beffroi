<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Claims;

use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use Heidi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\TestCase;

final class PublicSubjectIdentifierResolverTest extends TestCase
{
    /**
     * OIDC Core §8 "public": the same subject for every client, the one the core keeps for the user.
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

    /**
     * The way back is the same identifier read as itself, which is what it has always been: the string a
     * client presents is the one the core keeps, so the user is the one that string names.
     */
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

    /**
     * This kind is computed from nothing a client registers, so it demands nothing of a registration: a
     * client with no redirection URI at all takes it.
     */
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
