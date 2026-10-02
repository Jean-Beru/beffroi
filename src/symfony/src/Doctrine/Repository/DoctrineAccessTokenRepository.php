<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_merge;
use function array_values;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Listener\ClientResolver;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokenInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use function is_subclass_of;
use function sort;
use function usort;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Opaque access tokens, one table per kind (architecture §4.6, §5.3): the kinds are the entities mapped
 * under StoredAccessToken, read once from the metadata, as the kinds of credential are. A token somebody
 * signed in for keeps the session it descends from, a token a client holds for itself keeps no such column,
 * and neither row carries a column its kind has nothing to write in.
 *
 * A value says nothing of the kind it was drawn for, so it is looked up in every kind; what revokes by
 * session reaches only the kinds that have one, there being no session to end for the others. A token of a
 * client no longer registered is not found, and removed without being listed.
 */
final class DoctrineAccessTokenRepository implements
    AccessTokenRepositoryInterface,
    CanRevokeAccessTokenInterface,
    CanRevokeAccessTokensByConsentInterface,
    CanRevokeAccessTokensByGrantInterface,
    CanRevokeAccessTokensBySessionInterface
{
    /**
     * @var list<class-string<StoredAccessToken>>|null
     */
    private ?array $kinds = null;

    public function __construct(
        private readonly EntityManagers $managers,
    ) {
    }

    public function save(StoredAccessToken $token): void
    {
        $manager = $this->managers->forClass($token::class);
        $manager->persist($token);
        $manager->flush();
    }

    public function find(string $token): ?StoredAccessToken
    {
        $tokenHash = DrawnSecret::digestOf($token);
        foreach ($this->kinds() as $kind) {
            $record = $this->managers->forClass($kind)->find($kind, $tokenHash);
            if ($record !== null && ClientResolver::isResolved($record)) {
                return $record;
            }
        }

        return null;
    }

    public function revoke(StoredAccessToken $token): void
    {
        $this->remove([$token]);
    }

    public function revokeByGrant(Uuid $grantId): array
    {
        return $this->removeMatching([
            'grantId' => $grantId,
        ]);
    }

    /**
     * A token a client holds for itself descends from no session, so no logout reaches it: its kind has no
     * session to match on and is left alone here.
     */
    public function revokeBySession(Uuid $session): array
    {
        return $this->removeMatching([
            'session' => $session,
        ], StoredUserAccessToken::class);
    }

    /**
     * The user is a column of the session and not of the token, so the kinds that have one are asked by
     * a join where the others are asked by a criterion.
     */
    public function revokeByConsent(Consent $consent): array
    {
        $tokens = [];
        foreach ($this->kindsUnder(StoredUserAccessToken::class) as $kind) {
            /** @var list<StoredAccessToken> $ofThatKind */
            $ofThatKind = $this->managers
                ->forClass($kind)
                ->createQueryBuilder()
                ->select('t')
                ->from($kind, 't')
                ->join('t.session', 's')
                ->where('s.user = :user')
                ->andWhere('t.clientId = :clientId')
                ->setParameter('user', $consent->user->id, UuidType::NAME)
                ->setParameter('clientId', $consent->clientId)
                ->getQuery()
                ->getResult();
            $tokens = array_merge($tokens, $ofThatKind);
        }

        return $this->removeAll($tokens);
    }

    /**
     * @param array<string, mixed> $criteria
     * @param class-string<StoredAccessToken> $of the kinds this reaches
     *
     * @return list<StoredAccessToken> the rows removed, oldest first, those of an unregistered client left out
     */
    private function removeMatching(array $criteria, string $of = StoredAccessToken::class): array
    {
        $tokens = [];
        foreach ($this->kindsUnder($of) as $kind) {
            $tokens = array_merge($tokens, $this->managers
                ->forClass($kind)
                ->getRepository($kind)
                ->findBy($criteria, [
                    'issuedAt' => 'ASC',
                    'tokenHash' => 'ASC',
                ]));
        }

        return $this->removeAll($tokens);
    }

    /**
     * @param list<StoredAccessToken> $tokens
     *
     * @return list<StoredAccessToken> the rows removed, oldest first, those of an unregistered client left out
     */
    private function removeAll(array $tokens): array
    {
        usort($tokens, static fn (StoredAccessToken $a, StoredAccessToken $b): int => [$a->issuedAt, $a->tokenHash] <=> [$b->issuedAt, $b->tokenHash]);
        $this->remove($tokens);

        return array_values(array_filter($tokens, ClientResolver::isResolved(...)));
    }

    /**
     * @param class-string<StoredAccessToken> $of
     *
     * @return list<class-string<StoredAccessToken>>
     */
    private function kindsUnder(string $of): array
    {
        return array_values(array_filter(
            $this->kinds(),
            static fn (string $kind): bool => $kind === $of || is_subclass_of($kind, $of),
        ));
    }

    /**
     * @param list<StoredAccessToken> $tokens
     */
    private function remove(array $tokens): void
    {
        $managers = [];
        foreach ($tokens as $token) {
            $manager = $this->managers->forClass($token::class);
            $manager->remove($token);
            $managers[$token::class] = $manager;
        }
        foreach ($managers as $manager) {
            $manager->flush();
        }
    }

    /**
     * The entities mapped under StoredAccessToken, in a fixed order: what has a table of its own, and so a
     * kind of token the provider keeps. The mapped superclass is not one, and asking its repository for
     * rows would name a table nothing ever created.
     *
     * @return list<class-string<StoredAccessToken>>
     */
    private function kinds(): array
    {
        if ($this->kinds !== null) {
            return $this->kinds;
        }
        $kinds = [];
        foreach ($this->managers->all() as $manager) {
            foreach ($manager->getMetadataFactory()->getAllMetadata() as $metadata) {
                if ($metadata instanceof OrmClassMetadata && $metadata->isMappedSuperclass) {
                    continue;
                }
                $class = $metadata->getName();
                if (is_subclass_of($class, StoredAccessToken::class)) {
                    $kinds[] = $class;
                }
            }
        }
        sort($kinds);

        return $this->kinds = $kinds;
    }
}
