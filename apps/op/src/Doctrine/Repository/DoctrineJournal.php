<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use App\Doctrine\SelectionWithinAPeriod;
use App\Doctrine\EntityManagers;
use App\Doctrine\PageOfRows;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Journal\JournalQuestion;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\JournalInterface;
use function count;
use SortDirection;
use Symfony\Component\Uid\Uuid;
use function sprintf;
use DateTimeImmutable;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * @extends DoctrineRepository<JournalEntry>
 */
final readonly class DoctrineJournal extends DoctrineRepository implements JournalInterface, ActsOfAPersonInterface, CanPageActsOfAPersonInterface
{
    public const int FORGOTTEN_AT_ONCE = 1000;

    public function __construct(
        EntityManagers $managers,
        private PageOfRows $rows,
    ) {
        parent::__construct($managers, JournalEntry::class);
    }

    public function record(JournalEntry $entry): void
    {
        $this->store($this->namingTheRowOfItsTenant($entry));
    }

    /**
     * An act comes back from a queue, with a copy of its tenant the manager does not hold.
     */
    private function namingTheRowOfItsTenant(JournalEntry $entry): JournalEntry
    {
        $manager = $this->manager();
        if ($manager->contains($entry->tenant)) {
            return $entry;
        }
        $tenant = $manager->getReference(Tenant::class, $entry->tenant->id);
        if (! $tenant instanceof Tenant) {
            throw new RuntimeException(sprintf('The tenant "%s" of an act of the journal has no row.', $entry->tenant->slug));
        }

        return new JournalEntry($entry->id, $tenant, $entry->act, $entry->occurredAt, $entry->context, $entry->subject, $entry->client);
    }

    public function forgetBefore(Tenant $tenant, DateTimeImmutable $moment): int
    {
        /** @var list<JournalEntry> $past */
        $past = $this->queryBuilder('a')
            ->where('a.tenant = :tenant')
            ->andWhere('a.occurredAt < :moment')
            ->orderBy('a.occurredAt', SortDirection::Ascending)
            ->setMaxResults(self::FORGOTTEN_AT_ONCE)
            ->setParameter('tenant', $tenant->id, UuidType::NAME)
            ->setParameter('moment', $moment)
            ->getQuery()
            ->getResult();
        if ($past === []) {
            return 0;
        }
        $manager = $this->manager();
        foreach ($past as $entry) {
            $manager->remove($entry);
        }
        $manager->flush();

        return count($past);
    }

    /**
     * @return Listing<JournalEntry>
     */
    public function pageOfActs(User $user, JournalQuestion $question, Pagination $pagination): Listing
    {
        $theirs = $this->queryBuilder('a')
            ->where('a.tenant = :tenant')
            ->andWhere('a.subject = :subject')
            ->setParameter('tenant', $user->tenant->id, UuidType::NAME)
            ->setParameter('subject', $user->subject->value);
        if ($question->acts !== []) {
            $theirs->andWhere('a.act IN (:acts)')->setParameter('acts', $question->acts);
        }
        if ($question->client !== null) {
            $theirs->andWhere('a.client = :client')->setParameter('client', $question->client);
        }

        return $this->rows->of(
            JournalEntry::class,
            SelectionWithinAPeriod::narrow($theirs, 'a.occurredAt', $question->period),
            'a.id',
            $pagination,
        );
    }

    public function lastOf(User $user, array $acts, int $howMany): array
    {
        if ($acts === [] || $howMany < 1) {
            return [];
        }

        /** @var list<JournalEntry> $last */
        $last = $this->queryBuilder('a')
            ->where('a.tenant = :tenant')
            ->andWhere('a.subject = :subject')
            ->andWhere('a.act IN (:acts)')
            ->orderBy('a.id', SortDirection::Descending)
            ->setMaxResults($howMany)
            ->setParameter('tenant', $user->tenant->id, UuidType::NAME)
            ->setParameter('subject', $user->subject->value)
            ->setParameter('acts', $acts)
            ->getQuery()
            ->getResult();

        return $last;
    }

    /**
     * The identifier is a UUIDv7, so "greater than" is "later than".
     */
    public function everyActOf(User $user, int $howMany, ?Uuid $after = null): array
    {
        if ($howMany < 1) {
            return [];
        }
        $query = $this->queryBuilder('a')
            ->where('a.tenant = :tenant')
            ->andWhere('a.subject = :subject')
            ->orderBy('a.id', SortDirection::Ascending)
            ->setMaxResults($howMany)
            ->setParameter('tenant', $user->tenant->id, UuidType::NAME)
            ->setParameter('subject', $user->subject->value);
        if ($after !== null) {
            $query->andWhere('a.id > :after')->setParameter('after', $after, UuidType::NAME);
        }

        /** @var list<JournalEntry> $page */
        $page = $query->getQuery()->getResult();

        return $page;
    }
}
