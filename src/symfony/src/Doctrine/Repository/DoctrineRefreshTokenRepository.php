<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_values;
use function is_array;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Listener\ClientResolver;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Refresh tokens in beffroi_refresh_token (architecture §4.6). A token of a client no longer registered is
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
            'family' => $family,
        ]);
    }

    /**
     * The tokens one record read once granted, which their family names. A join and not a criterion: the
     * family is a row of its own, and a criterion of findBy() does not reach through an association
     * (issue #440).
     */
    public function findByAuthorizationCode(string $codeHash): array
    {
        $tokens = $this->queryBuilder('token')
            ->join('token.family', 'family')
            ->where('family.grantingRecordHash = :hash')
            ->setParameter('hash', $codeHash)
            ->orderBy('token.issuedAt', 'ASC')
            ->addOrderBy('token.tokenHash', 'ASC')
            ->getQuery()
            ->getResult();

        return $this->onlyResolved(is_array($tokens) ? $tokens : []);
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
        return $this->onlyResolved($this->repository()->findBy($criteria, [
            'issuedAt' => 'ASC',
            'tokenHash' => 'ASC',
        ]));
    }

    /**
     * @param array<array-key, mixed> $tokens
     *
     * @return list<RefreshToken>
     */
    private function onlyResolved(array $tokens): array
    {
        return array_values(array_filter(
            $tokens,
            static fn (mixed $token): bool => $token instanceof RefreshToken && ClientResolver::isResolved($token),
        ));
    }
}
