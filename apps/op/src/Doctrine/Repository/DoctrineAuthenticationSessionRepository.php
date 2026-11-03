<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use function array_values;
use function array_filter;
use Beffroi\Core\Domain\Listing\Period;
use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\QueryBuilder;
use App\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Record\WhatATokenStillNeeds;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CanFindUnendedSessionsInterface;
use Beffroi\Core\Port\CanPageActiveSessionsInterface;
use Beffroi\Core\Port\DeadRecordsInterface;
use Beffroi\Core\Port\SubjectsOfSessionsInterface;
use function is_array;
use SortDirection;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Sessions in beffroi_authentication_session (architecture §3.2, §3.4). A DQL parameter that is an
 * identifier names its type: the ORM would infer a string from a Uuid.
 *
 * @extends DoctrineRepository<AuthenticationSession>
 */
final readonly class DoctrineAuthenticationSessionRepository extends DoctrineRepository implements
    AuthenticationSessionRepositoryInterface,
    CanFindUnendedSessionsInterface,
    CanPageActiveSessionsInterface,
    DeadRecordsInterface,
    SubjectsOfSessionsInterface
{
    public function __construct(
        EntityManagers $managers,
        private BoundedDelete $sweep,
        private WhatATokenStillNeeds $stillNeeded,
    ) {
        parent::__construct($managers, AuthenticationSession::class);
    }

    /**
     * A session outlives itself (issue #177). It is not kept because somebody may sign in on it again, a
     * session that ended or expired being over for good, but because an access token somebody signed in for
     * names it, and a resource server asks this row whether the session it descends from was ended
     * (AccessTokenInspector): dropping it turns a token this provider would have answered for into a token
     * it refuses. So it waits what a token still needs, counted from the instant it stopped being able to
     * grant anything.
     *
     * **The expiry and not the end.** A session that was ended early stopped granting then, but its expiry
     * is the later of the two and the only one an index reads, and nothing but a longer wait follows from
     * taking it.
     *
     * **What cascades off it is worth nothing by then.** The authorization codes, the refresh tokens and the
     * access tokens of a login name this row under a foreign key that cascades, so dropping it drops them.
     * A code of the last minute of a session has its own instant up to a code lifetime after this one, and
     * the cascade takes it that much early; by then the lineage it granted is over, its own absolute expiry
     * being counted from an issuance inside the session, and no access token of its grant can be presented
     * either. So the cascade only ever reaches rows nothing could have read again.
     */
    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $expiry = $this->sweep->column(AuthenticationSession::class, 'expiresAt');

        return $this->sweep->from(
            AuthenticationSession::class,
            $tenant,
            sprintf('%s <= :dead', $expiry),
            $expiry,
            [
                'dead' => $this->stillNeeded->deadBefore($now),
            ],
            [
                'dead' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );
    }

    public function find(Uuid $id): ?AuthenticationSession
    {
        return $this->repository()->findOneBy([
            'id' => $id,
        ]);
    }

    /**
     * One column of one row, the subject of the person the session names, which stays in the clear (decision
     * 0011). A scalar read loads neither the session nor the person, so nothing either of them seals is opened,
     * where reading the session would open its columns and those of the person it is loaded with.
     */
    public function of(Uuid $session): Subject
    {
        $row = $this->queryBuilder('s')
            ->select('u.subject')
            ->join('s.user', 'u')
            ->where('s.id = :session')
            ->setParameter('session', $session, UuidType::NAME)
            ->getQuery()
            ->getOneOrNullResult();
        $subject = is_array($row) ? $row['subject'] ?? null : null;

        return $subject instanceof Subject ? $subject : throw new RuntimeException(sprintf('No session "%s" names a person.', $session->toRfc4122()));
    }

    /**
     * The sessions of this person are a handful: they end and they expire, where a journal grows without
     * end, so the page is taken of what the query above answers and not of the table.
     *
     * @return Listing<AuthenticationSession>
     */
    public function pageOfActiveSessions(User $user, DateTimeImmutable $now, Pagination $pagination, ?Period $period = null): Listing
    {
        return Listing::of(
            array_values(array_filter(
                $this->findActiveByUser($user, $now),
                static fn (AuthenticationSession $session): bool => $period?->holds($session->establishedAt) !== false,
            )),
            $pagination,
        );
    }

    public function findActiveByUser(User $user, DateTimeImmutable $now): array
    {
        /** @var list<AuthenticationSession> */
        return $this->unendedOf($user)->andWhere('s.expiresAt > :now')->setParameter('now', $now, Types::DATETIME_IMMUTABLE)->getQuery()->getResult();
    }

    public function findUnendedByUser(User $user): array
    {
        /** @var list<AuthenticationSession> */
        return $this->unendedOf($user)->getQuery()->getResult();
    }

    /**
     * The sessions of one person that nothing has ended, in the order they were opened: an active session is one of
     * them that has not expired either.
     */
    private function unendedOf(User $user): QueryBuilder
    {
        return $this->queryBuilder('s')
            ->where('s.user = :user')
            ->andWhere('s.endedAt IS NULL')
            ->orderBy('s.establishedAt', SortDirection::Ascending)
            ->addOrderBy('s.id', SortDirection::Ascending)
            ->setParameter('user', $user->id, UuidType::NAME);
    }

    public function save(AuthenticationSession $session): void
    {
        $this->store($session);
    }
}
