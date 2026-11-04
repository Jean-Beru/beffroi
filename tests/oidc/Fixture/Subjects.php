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
 * OIDC Core §8
 */
final class Subjects
{
    public static function ofAProvider(?UserRepositoryInterface $users = null): AssignedSubjectIdentifiers
    {
        return new AssignedSubjectIdentifiers([self::publicKind($users)]);
    }

    public static function personOfAToken(
        ?UserRepositoryInterface $users = null,
        ?PresentedSubjectReaderInterface $subjects = null,
    ): PersonOfAnAccessToken {
        $users ??= new InMemoryUserRepository();

        return new PersonOfAnAccessToken($users, $subjects ?? self::ofAProvider($users));
    }

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

    public static function bothKinds(
        ?UserRepositoryInterface $users = null,
        ?PairwiseSaltInterface $salts = null,
        ?PairwiseSubjectRepositoryInterface $assigned = null,
    ): AssignedSubjectIdentifiers {
        return new AssignedSubjectIdentifiers([self::publicKind($users), self::pairwiseKind($salts, $assigned)]);
    }
}
