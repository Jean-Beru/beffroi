<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use function array_slice;
use function in_array;
use function usort;
use Symfony\Component\Uid\Uuid;

final class RecordedActs implements ActsOfAPersonInterface
{
    /**
     * @var array<string, JournalEntry>
     */
    private array $acts = [];

    public function record(JournalEntry $entry): void
    {
        $this->acts[$entry->id->toRfc4122()] = $entry;
    }

    public function lastOf(User $user, array $acts, int $howMany): array
    {
        if ($acts === [] || $howMany < 1) {
            return [];
        }
        $found = $this->ofTheirs($user, $acts);
        usort($found, static fn (JournalEntry $a, JournalEntry $b): int => $b->id->compare($a->id));

        return array_slice($found, 0, $howMany);
    }

    public function everyActOf(User $user, int $howMany, ?Uuid $after = null): array
    {
        if ($howMany < 1) {
            return [];
        }
        $found = [];
        foreach ($this->ofTheirs($user) as $act) {
            if ($after === null || $act->id->compare($after) > 0) {
                $found[] = $act;
            }
        }
        usort($found, static fn (JournalEntry $a, JournalEntry $b): int => $a->id->compare($b->id));

        return array_slice($found, 0, $howMany);
    }

    /**
     * @param list<string>|null $named
     *
     * @return list<JournalEntry>
     */
    private function ofTheirs(User $user, ?array $named = null): array
    {
        $found = [];
        foreach ($this->acts as $act) {
            if (! $act->tenant->equals($user->tenant) || $act->subject?->equals($user->subject) !== true) {
                continue;
            }
            if ($named === null || in_array($act->act, $named, true)) {
                $found[] = $act;
            }
        }

        return $found;
    }
}
