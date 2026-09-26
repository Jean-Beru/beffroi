<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_values;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Heidi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Refresh tokens in heidi_refresh_token (architecture §4.6). A token of a client no longer registered is
 * not found and not listed.
 *
 * @extends DoctrineRepository<RefreshToken>
 */
final readonly class DoctrineRefreshTokenRepository extends DoctrineRepository implements RefreshTokenRepositoryInterface, RefreshTokensOfAConsentInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, RefreshToken::class);
    }

    public function findByTokenHash(string $tokenHash): ?RefreshToken
    {
        $token = $this->repository()->findOneBy([
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
            'family.grantingRecordHash' => $codeHash,
        ]);
    }

    public function findBySession(Uuid $session): array
    {
        return $this->resolved([
            'session' => $session,
        ]);
    }

    /**
     * @return list<RefreshToken>
     */
    public function ofConsent(Consent $consent): array
    {
        /** @var list<RefreshToken> $tokens */
        $tokens = $this->queryBuilder('t')
            ->join('t.session', 's')
            ->where('s.user = :user')
            ->andWhere('t.clientId = :clientId')
            ->orderBy('t.issuedAt', 'ASC')
            ->addOrderBy('t.tokenHash', 'ASC')
            ->setParameter('user', $consent->user->id, UuidType::NAME)
            ->setParameter('clientId', $consent->clientId)
            ->getQuery()
            ->getResult();

        return array_values(array_filter($tokens, ClientResolver::isResolved(...)));
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
        $tokens = $this->repository()->findBy($criteria, [
            'issuedAt' => 'ASC',
            'tokenHash' => 'ASC',
        ]);

        return array_values(array_filter($tokens, ClientResolver::isResolved(...)));
    }
}
