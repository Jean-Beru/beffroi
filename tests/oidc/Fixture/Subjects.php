<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Application\Claims\AssignedSubjectIdentifiers;
use Beffroi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Beffroi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Oidc\Application\Token\PersonOfAnAccessToken;
use Beffroi\Oidc\Application\Token\SealedPerson;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPairwiseSalt;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPairwiseSubjectRepository;
use Beffroi\Oidc\Port\PairwiseSaltInterface;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
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

    /**
     * The one reading a resource of the provider does of the person a token is about (issue #601): off the
     * record, where whatever issued the token resolved one, and off the "sub" for its client where nothing
     * did.
     */
    public static function personOfAToken(
        ?UserRepositoryInterface $users = null,
        ?PresentedSubjectReaderInterface $subjects = null,
    ): PersonOfAnAccessToken {
        $users ??= new InMemoryUserRepository();

        return new PersonOfAnAccessToken($users, $subjects ?? self::ofAProvider($users));
    }

    /**
     * The person a self-contained token says it is about (issue #641), sealed as a deployment seals it: the
     * sealer of the tests writes the tenant into the envelope and reads it back, so an envelope of one
     * tenant does not open for another here either.
     */
    public static function sealedPerson(?SecretSealerInterface $sealer = null): SealedPerson
    {
        return new SealedPerson($sealer ?? new FakeSecretSealer());
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
            Sectors::ofAProvider(),
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
