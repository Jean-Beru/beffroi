<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_filter;
use function array_slice;
use function array_values;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Journal\Link;
use Beffroi\Core\Domain\Journal\LinkedAct;
use Beffroi\Core\Domain\Journal\WrittenAct;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\ChainOfActsInterface;
use Beffroi\Core\Port\JournalInterface;
use function count;
use DateTimeImmutable;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use function ksort;
use Symfony\Component\Uid\Uuid;

/**
 * A journal of one tenant whose rows a test can rewrite as whoever holds the database would.
 */
final class ChainOfWrittenActs implements ChainOfActsInterface, JournalInterface
{
    public private(set) Link $head;

    public private(set) int $locks = 0;

    /**
     * @var array<int, LinkedAct> by position
     */
    private array $links = [];

    private int $unlinked = 0;

    public function __construct()
    {
        $this->head = Link::beforeTheFirst();
    }

    public function write(string $act = 'user.authenticated', ?DateTimeImmutable $occurredAt = null): Link
    {
        return $this->append(self::act($act, $occurredAt ?? Fixtures::now()));
    }

    public static function act(string $act, DateTimeImmutable $occurredAt, ?string $subject = 'alice-subject'): WrittenAct
    {
        return new WrittenAct(Uuid::v7()->toRfc4122(), Uuid::v7()->toRfc4122(), $act, $occurredAt, $subject, null, null, 'sealed provenance');
    }

    public function record(JournalEntry $entry): void
    {
        $this->append(new WrittenAct(
            $entry->id->toRfc4122(),
            $entry->tenant->id->toRfc4122(),
            $entry->act,
            $entry->occurredAt,
            $entry->subject?->value,
            $entry->client,
            $entry->author?->value,
            json_encode($entry->context->toDocument(), JSON_THROW_ON_ERROR),
        ));
    }

    public function forgetUpTo(Tenant $tenant, int $position): int
    {
        $before = count($this->links);
        $this->links = array_filter($this->links, static fn (LinkedAct $linked): bool => $linked->position > $position);

        return $before - count($this->links);
    }

    public function rewrite(int $position, WrittenAct $act): void
    {
        $linked = $this->links[$position];
        $this->links[$position] = new LinkedAct($act, $linked->position, $linked->previous, $linked->hash);
    }

    /**
     * Each link from that position on computed again, as whoever holds the database can.
     */
    public function rewriteAndRelink(int $position, WrittenAct $act): void
    {
        $this->rewrite($position, $act);
        $before = new Link($position - 1, $this->links[$position]->previous);
        ksort($this->links);
        foreach ($this->links as $at => $linked) {
            if ($at < $position) {
                continue;
            }
            $link = $before->then($linked->act);
            $this->links[$at] = new LinkedAct($linked->act, $at, $before->hash, $link->hash);
            $before = $link;
        }
        $this->head = $before;
    }

    public function remove(int $position): void
    {
        unset($this->links[$position]);
    }

    public function insertWithoutALink(): void
    {
        ++$this->unlinked;
    }

    public function lockedHead(Tenant $tenant): Link
    {
        ++$this->locks;

        return $this->head;
    }

    public function head(Tenant $tenant): Link
    {
        return $this->head;
    }

    public function linkedAfter(Tenant $tenant, int $position, int $howMany): array
    {
        ksort($this->links);

        return array_slice(array_values(array_filter($this->links, static fn (LinkedAct $linked): bool => $linked->position > $position)), 0, $howMany);
    }

    public function actsOutsideTheChain(Tenant $tenant, int $keptAfter): int
    {
        return $this->unlinked + count(array_filter($this->links, static fn (LinkedAct $linked): bool => $linked->position <= $keptAfter));
    }

    private function append(WrittenAct $act): Link
    {
        $link = $this->head->then($act);
        $this->links[$link->position] = new LinkedAct($act, $link->position, $this->head->hash, $link->hash);
        $this->head = $link;

        return $link;
    }
}
