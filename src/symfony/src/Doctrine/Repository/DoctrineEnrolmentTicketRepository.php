<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use Beffroi\Core\Port\EnrolmentTicketRepositoryInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Types\Types;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * The enrolment tickets, in beffroi_enrolment_ticket (architecture §3.1, issue #613). The lookup is by
 * identifier: the row holds a hash of the value, salted, so nothing is found by the value itself.
 *
 * **A ticket spent or out of time can no longer do anything** and is swept with the other dead rows
 * (issue #177): what it opened is in the journal of its person and in the credential it posed, and a row
 * that opens nothing is not an act of anybody.
 *
 * @extends DoctrineRepository<EnrolmentTicket>
 */
final readonly class DoctrineEnrolmentTicketRepository extends DoctrineRepository implements DeadRecordsInterface, EnrolmentTicketRepositoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private BoundedDelete $sweep,
    ) {
        parent::__construct($managers, EnrolmentTicket::class);
    }

    public function find(Uuid $id): ?EnrolmentTicket
    {
        return $this->repository()->find($id);
    }

    /**
     * @return list<EnrolmentTicket>
     */
    public function unspentOf(User $user): array
    {
        return $this->repository()->findBy([
            'user' => $user,
            'spentAt' => null,
        ], [
            'createdAt' => 'ASC',
            'id' => 'ASC',
        ]);
    }

    public function save(EnrolmentTicket $ticket): void
    {
        $this->store($ticket);
    }

    public function forget(EnrolmentTicket $ticket): void
    {
        $this->discard($ticket);
    }

    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $expiry = $this->sweep->column(EnrolmentTicket::class, 'expiresAt');
        $spent = $this->sweep->column(EnrolmentTicket::class, 'spentAt');

        return $this->sweep->from(
            EnrolmentTicket::class,
            $tenant,
            sprintf('(%s <= :dead OR %s IS NOT NULL)', $expiry, $spent),
            $expiry,
            [
                'dead' => $now,
            ],
            [
                'dead' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );
    }
}
