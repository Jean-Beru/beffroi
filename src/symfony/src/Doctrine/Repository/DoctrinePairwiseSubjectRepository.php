<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Doctrine\DBAL\Types\Types;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Type\SectorIdentifierType;
use Beffroi\Bundle\Doctrine\Type\SubjectType;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Claims\PairwiseSubject;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use function sprintf;

/**
 * What each sector of a tenant has seen a user under, in beffroi_pairwise_subject (OIDC Core §8.1).
 *
 * @extends DoctrineRepository<PairwiseSubject>
 */
final readonly class DoctrinePairwiseSubjectRepository extends DoctrineRepository implements PairwiseSubjectRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, PairwiseSubject::class);
    }

    public function findUser(Tenant $tenant, SectorIdentifier $sector, Subject $subject): ?User
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'sector' => $sector,
            'subject' => $subject,
        ])?->user;
    }

    /**
     * One INSERT through the connection and not the unit of work, as an initial access token is spent:
     * the same user and the same sector give the same identifier at every document written afterwards, so
     * the row is written once and the writes that follow are asked to do nothing. Two workers issuing the
     * first two tokens of a user at the same moment race into the unique index, where one of them loses
     * and neither fails, which is what a flush of the unit of work could not promise.
     */
    public function record(PairwiseSubject $assigned): void
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(PairwiseSubject::class);
        $manager->getConnection()->executeStatement(
            sprintf(
                'INSERT INTO %s (%s, %s, %s, %s, %s, %s) VALUES (:id, :tenant, :user, :sector, :subject, :assignedAt) ON CONFLICT DO NOTHING',
                $metadata->getTableName(),
                $metadata->getColumnName('id'),
                $metadata->getSingleAssociationJoinColumnName('tenant'),
                $metadata->getSingleAssociationJoinColumnName('user'),
                $metadata->getColumnName('sector'),
                $metadata->getColumnName('subject'),
                $metadata->getColumnName('assignedAt'),
            ),
            [
                'id' => $assigned->id,
                'tenant' => $assigned->tenant->id,
                'user' => $assigned->user->id,
                'sector' => $assigned->sector,
                'subject' => $assigned->subject,
                'assignedAt' => $assigned->assignedAt,
            ],
            [
                'id' => 'uuid',
                'tenant' => 'uuid',
                'user' => 'uuid',
                'sector' => SectorIdentifierType::NAME,
                'subject' => SubjectType::NAME,
                'assignedAt' => Types::DATETIME_IMMUTABLE,
            ],
        );
    }
}
