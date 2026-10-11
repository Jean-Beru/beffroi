<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use function array_map;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Journal\JournalQuestion;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use function count;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use function json_encode;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * What happened in the name of one person, for whoever answers for the instance (issue #591): one row per
 * act of their journal over a stretch of time, most recent first, each with the application it was done on
 * behalf of and where the request came from.
 *
 * It is the console counterpart of the page that shows the same rows, as "beffroi:user:applications" is of
 * the applications of an account. It reads and writes nothing: a request under article 15 of the GDPR is
 * answered from here, and the person reads the same acts in their own archive.
 *
 * **It says what the journal does not have.** A reading asked for a stretch of time the retention cannot
 * cover is answered with the duration this deployment keeps and the day it reaches, never with an empty
 * table: a register that looks complete and is not is worse than one that says where it stops.
 */
#[AsCommand(
    name: self::NAME,
    description: 'List the acts of a user over a period, with the application each one was done on behalf of; for answering a request about what happened in their name.',
)]
final readonly class UserJournalCommand
{
    public const string NAME = 'beffroi:user:journal';

    public const string TABLE = 'table';

    public const string JSON = 'json';

    /**
     * How many acts one page reads. A bound and not a tuning, as the chapter of the archive has one: what
     * fixes how much is printed is the period and the retention, and this fixes how much is in memory at
     * once.
     */
    public const int READ_AT_ONCE = 200;

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private CanPageActsOfAPersonInterface $acts,
        private JournalRetention $retention,
    ) {
    }

    /**
     * @param list<string> $act
     */
    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user.')]
        string $username,
        #[Option(description: 'The first day to read, as YYYY-MM-DD on UTC, that day included; the whole of what the journal holds when not given.')]
        ?string $from = null,
        #[Option(description: 'The last day to read, as YYYY-MM-DD on UTC, that day included.')]
        ?string $to = null,
        #[Option(description: 'The name of an act to read, as the journal writes it ("tokens.issued"), repeatable; every act when not given.')]
        array $act = [],
        #[Option(description: 'The application the acts were done on behalf of, by the identifier it was registered under; every application when not given.')]
        ?string $client = null,
        #[Option(description: 'How the acts are written: a table to read, or JSON for a document a request is answered with.')]
        string $format = self::TABLE,
    ): int {
        if ($format !== self::TABLE && $format !== self::JSON) {
            $io->error(sprintf('The format "%s" is neither "%s" nor "%s".', $format, self::TABLE, self::JSON));

            return Command::FAILURE;
        }
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        try {
            $period = Period::ofDays(self::day($from, 'from'), self::day($to, 'to'));
        } catch (InvalidArgumentException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }
        $acts = $this->everyActOf($user, new JournalQuestion($act, $client, $period));

        return $format === self::JSON
            ? $this->writeDocument($io, $user, $period, $acts)
            : $this->writeTable($io, $user, $period, $acts);
    }

    /**
     * The whole of what the question asks, read page by page: the journal of a person is not a query that
     * holds the table, and what a reading of it prints is every row it asked for.
     *
     * @return list<JournalEntry>
     */
    private function everyActOf(User $user, JournalQuestion $question): array
    {
        $acts = [];
        $number = 1;
        do {
            $page = $this->acts->pageOfActs($user, $question, new Pagination($number, self::READ_AT_ONCE));
            foreach ($page as $entry) {
                $acts[] = $entry;
            }
            ++$number;
        } while ($page->hasNext());

        return $acts;
    }

    /**
     * @param list<JournalEntry> $acts
     */
    private function writeTable(SymfonyStyle $io, User $user, ?Period $period, array $acts): int
    {
        $io->title(sprintf('Journal of "%s"', $user->username));
        if ($acts === []) {
            $io->text(sprintf('The journal holds no act of "%s" over that stretch of time.', $user->username));
        } else {
            $io->table(
                ['Act', 'Occurred (UTC)', 'Application', 'From'],
                array_map(static fn (JournalEntry $entry): array => [
                    $entry->act,
                    $entry->occurredAt->format('Y-m-d H:i:s'),
                    $entry->client ?? '',
                    $entry->context->ipAddress ?? 'address not recorded',
                ], $acts),
            );
            $io->text(sprintf('%d act(s), most recent first.', count($acts)));
        }
        $io->text($this->whereTheJournalStops($period));

        return Command::SUCCESS;
    }

    /**
     * A document and not a terminal, because what a register is attached to is a file: the same shape the
     * journal chapter of an archive writes, with what the retention can answer for beside it.
     *
     * @param list<JournalEntry> $acts
     */
    private function writeDocument(SymfonyStyle $io, User $user, ?Period $period, array $acts): int
    {
        $io->writeln(json_encode(
            [
                'username' => $user->username,
                'sub' => $user->subject->value,
                'period' => [
                    'from' => ArchivedFacts::moment($period?->from),
                    'to' => ArchivedFacts::moment($period?->to),
                ],
                'kept' => [
                    'days' => $this->retention->days,
                    'since' => ArchivedFacts::moment($this->retention->keptSince()),
                ],
                'acts' => array_map(ArchivedFacts::act(...), $acts),
            ],
            JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES,
        ));

        return Command::SUCCESS;
    }

    /**
     * What this deployment keeps, said whenever the reading reaches past it: a period that starts before
     * the retention holds anything, and a reading that named no first day at all.
     */
    private function whereTheJournalStops(?Period $period): string
    {
        $since = $this->retention->keptSince();
        $covered = $period?->from !== null && $period->from >= $since;

        return $covered
            ? sprintf('This deployment keeps an act %d day(s); the whole of that period is inside it.', $this->retention->days)
            : sprintf(
                'This deployment keeps an act %d day(s): nothing that happened before %s is held, whatever this reading asked for.',
                $this->retention->days,
                $since->format('Y-m-d H:i:s'),
            );
    }

    /**
     * A day as the shell handed it over, on UTC, which is the clock the rows are held on: the pages of an
     * account are where a date is read in the time zone of the person (issue #469); a register attached to
     * an answer says one clock.
     *
     * @throws InvalidArgumentException when it is not a day
     */
    private static function day(?string $asked, string $option): ?DateTimeImmutable
    {
        if ($asked === null || $asked === '') {
            return null;
        }
        $day = DateTimeImmutable::createFromFormat('!Y-m-d', $asked, new DateTimeZone('UTC'));
        if ($day === false) {
            throw new InvalidArgumentException(sprintf('The option "--%s" takes a day as YYYY-MM-DD, "%s" given.', $option, $asked));
        }

        return $day;
    }
}
