<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_merge;
use function array_values;
use Doctrine\ORM\Mapping\ClassMetadata as OrmClassMetadata;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Domain\Token\StoredUserAccessToken;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokenInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use function is_subclass_of;
use function sort;
use function usort;
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
     * @param array<string, mixed> $criteria
     * @param class-string<StoredAccessToken> $of the kinds this reaches
     *
     * @return list<StoredAccessToken> the rows removed, oldest first, those of an unregistered client left out
     */
    private function removeMatching(array $criteria, string $of = StoredAccessToken::class): array
    {
        $tokens = [];
        foreach ($this->kinds() as $kind) {
            if (! is_subclass_of($kind, $of) && $kind !== $of) {
                continue;
            }
            $tokens = array_merge($tokens, $this->managers
                ->forClass($kind)
                ->getRepository($kind)
                ->findBy($criteria, [
                    'issuedAt' => 'ASC',
                    'tokenHash' => 'ASC',
                ]));
        }
        usort($tokens, static fn (StoredAccessToken $a, StoredAccessToken $b): int => [$a->issuedAt, $a->tokenHash] <=> [$b->issuedAt, $b->tokenHash]);
        $this->remove($tokens);

        return array_values(array_filter($tokens, ClientResolver::isResolved(...)));
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
