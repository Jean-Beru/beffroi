<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_values;
use DateTimeImmutable;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokenInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Opaque access tokens in heidi_access_token (architecture §4.6). A token of a client no longer registered
 * is not found, and removed without being listed.
 *
 * @extends DoctrineRepository<StoredAccessToken>
 */
final readonly class DoctrineAccessTokenRepository extends DoctrineRepository implements
    AccessTokenRepositoryInterface,
    CanRevokeAccessTokenInterface,
    CanRevokeAccessTokensByGrantInterface,
    CanRevokeAccessTokensBySessionInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, StoredAccessToken::class);
    }

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): string
    {
        $value = DrawnSecret::draw();
        $this->store(StoredAccessToken::fromAuthorization(DrawnSecret::digestOf($value), $authorization, $now, $expiresAt));

        return $value;
    }

    public function find(string $token): ?StoredAccessToken
    {
        $record = $this->repository()->findOneBy([
            'tokenHash' => DrawnSecret::digestOf($token),
        ]);

        return $record !== null && ClientResolver::isResolved($record) ? $record : null;
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

    public function revokeBySession(Uuid $session): array
    {
        return $this->removeMatching([
            'session' => $session,
        ]);
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return list<StoredAccessToken> the rows removed, those of an unregistered client left out
     */
    private function removeMatching(array $criteria): array
    {
        $tokens = $this->repository()->findBy($criteria, [
            'issuedAt' => 'ASC',
            'tokenHash' => 'ASC',
        ]);
        $this->remove($tokens);

        return array_values(array_filter($tokens, ClientResolver::isResolved(...)));
    }

    /**
     * @param list<StoredAccessToken> $tokens
     */
    private function remove(array $tokens): void
    {
        $manager = $this->manager();
        foreach ($tokens as $token) {
            $manager->remove($token);
        }
        $manager->flush();
    }
}
