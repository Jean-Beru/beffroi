<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use function array_filter;
use function array_values;
use function is_array;
use App\Doctrine\EntityManagers;
use App\Doctrine\Listener\ClientResolver;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Domain\Token\RefreshTokenFamily;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use SortDirection;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Refresh tokens in beffroi_refresh_token (architecture §4.6). A token of a client no longer registered is
 * not found and not listed.
 *
 * @extends DoctrineRepository<RefreshToken>
 */
final readonly class DoctrineRefreshTokenRepository extends DoctrineRepository implements
    DeadRecordsInterface,
    RefreshTokenRepositoryInterface,
    RefreshTokensOfAConsentInterface
{
    public function __construct(
        EntityManagers $managers,
        private BoundedDelete $sweep,
    ) {
        parent::__construct($managers, RefreshToken::class);
    }

    /**
     * A rotated or revoked token stays so that a reuse is told from a token nobody ever issued (RFC 9700
     * §4.13.2), and what ends that is not its own sliding expiry but the absolute lifetime of its family,
     * which no rotation extends (architecture §4.6): a reuse of the first token of a lineage matters for as
     * long as the last one could be refreshed. So the lineage is read and never a duration, the date being
     * a column of the family.
     *
     * **The two tables are one store and two bounded statements**, and what orders them is the NOT EXISTS
     * and not the order they are made in: a family is a row every token of the lineage names, under a
     * foreign key that cascades nothing, so a family dropped while one of its tokens is still there would
     * be a statement that fails. A family whose tokens a bounded statement did not all reach is therefore
     * left where it is, whatever that statement reached, and the next run takes it.
     */
    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $familyOfToken = $this->sweep->joinColumn(RefreshToken::class, 'family');
        $familyKey = $this->sweep->column(RefreshTokenFamily::class, 'id');
        $familyExpiry = $this->sweep->column(RefreshTokenFamily::class, 'expiresAt');
        $families = $this->sweep->table(RefreshTokenFamily::class);

        $forgotten = $this->sweep->from(
            RefreshToken::class,
            $tenant,
            sprintf(
                '%s IN (SELECT %s FROM %s WHERE %s <= :now)',
                $familyOfToken,
                $familyKey,
                $families,
                $familyExpiry,
            ),
            $this->sweep->column(RefreshToken::class, 'issuedAt'),
            [
                'now' => $now,
            ],
            [
                'now' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );

        return $forgotten
        + $this->sweep->from(
            RefreshTokenFamily::class,
            $tenant,
            sprintf(
                '%s <= :now AND NOT EXISTS (SELECT 1 FROM %s WHERE %s = %s.%s)',
                $familyExpiry,
                $this->sweep->table(RefreshToken::class),
                $familyOfToken,
                $families,
                $familyKey,
            ),
            $familyExpiry,
            [
                'now' => $now,
            ],
            [
                'now' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );
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
            ->orderBy('token.issuedAt', SortDirection::Ascending)
            ->addOrderBy('token.tokenHash', SortDirection::Ascending)
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
            ->orderBy('t.issuedAt', SortDirection::Ascending)
            ->addOrderBy('t.tokenHash', SortDirection::Ascending)
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
