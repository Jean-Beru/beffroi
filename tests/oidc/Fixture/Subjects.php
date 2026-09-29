<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Bridge\Random\PlatformRandomness;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Application\Claims\AssignedSubjectIdentifiers;
use Heidi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Bridge\InMemory\InMemoryPairwiseSalt;
use Heidi\Oidc\Bridge\InMemory\InMemoryPairwiseSubjectRepository;
use Heidi\Oidc\Port\PairwiseSaltInterface;
use Heidi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;

/**
 * The kinds of "sub" a provider of the tests assigns (OIDC Core §8), wired as a deployment wires them: the
 * public kind first, which is what a client that registers none takes, and the pairwise kind beside it.
 */
final class Subjects
{
    /**
     * The wiring a test that cares about neither kind takes: the public one alone, over a repository of its
     * own unless the test holds one.
     */
    public static function ofAProvider(?UserRepositoryInterface $users = null): AssignedSubjectIdentifiers
    {
        return new AssignedSubjectIdentifiers([self::publicKind($users)]);
    }

    public static function publicKind(?UserRepositoryInterface $users = null): PublicSubjectIdentifierResolver
    {
        return new PublicSubjectIdentifierResolver($users ?? new InMemoryUserRepository());
    }

    public static function pairwiseKind(
        ?PairwiseSaltInterface $salts = null,
        ?PairwiseSubjectRepositoryInterface $assigned = null,
        ?ClockInterface $clock = null,
    ): PairwiseSubjectIdentifierResolver {
        return new PairwiseSubjectIdentifierResolver(
            $salts ?? new InMemoryPairwiseSalt(new PlatformRandomness()),
            $assigned ?? new InMemoryPairwiseSubjectRepository(),
            new SymfonyUuidGenerator(),
            $clock ?? new MockClock('2026-09-15T12:00:00+00:00'),
        );
    }

    /**
     * Both kinds, in the order a deployment wires them.
     */
    public static function bothKinds(
        ?UserRepositoryInterface $users = null,
        ?PairwiseSaltInterface $salts = null,
        ?PairwiseSubjectRepositoryInterface $assigned = null,
    ): AssignedSubjectIdentifiers {
        return new AssignedSubjectIdentifiers([self::publicKind($users), self::pairwiseKind($salts, $assigned)]);
    }
}
