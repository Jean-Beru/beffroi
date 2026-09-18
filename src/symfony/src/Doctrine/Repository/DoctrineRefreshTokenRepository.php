<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_values;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Refresh tokens in heidi_refresh_token (architecture §4.6). A token of a client no longer registered is
 * not found and not listed.
 *
 * @extends DoctrineRepository<RefreshToken>
 */
final readonly class DoctrineRefreshTokenRepository extends DoctrineRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, RefreshToken::class);
    }

    public function findByTokenHash(string $tokenHash): ?RefreshToken
    {
        $token = $this->repository()
            ->findOneBy([
                'tokenHash' => $tokenHash,
            ]);

        return $token !== null && ClientResolver::isResolved($token) ? $token : null;
    }

    public function findByFamily(Uuid $family): array
    {
        return $this->resolved([
            'family.id' => $family,
        ]);
    }

    public function findByAuthorizationCode(string $codeHash): array
    {
        return $this->resolved([
            'family.authorizationCodeHash' => $codeHash,
        ]);
    }

    public function findBySession(Uuid $session): array
    {
        return $this->resolved([
            'session' => $session,
        ]);
    }

    public function save(RefreshToken $token): void
    {
        $this->store($token);
    }

    /**
     * @param array<string, mixed> $criteria
     *
     * @return list<RefreshToken>
     */
    private function resolved(array $criteria): array
    {
        $tokens = $this->repository()
            ->findBy($criteria, [
                'issuedAt' => 'ASC',
                'tokenHash' => 'ASC',
            ]);

        return array_values(array_filter($tokens, ClientResolver::isResolved(...)));
    }
}
