<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ArchiveChapterInterface;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page where a person asks for everything this provider holds about them, and downloads it once it is
 * ready (RGPD articles 15 and 20, issue #453).
 *
 * **It always says which of the four states it is in**, because the one answer a page like this may not
 * give is nothing: a person who clicked and sees the same page cannot tell a request that is being worked
 * on from a request that was lost. An archive still being built says so, one that has expired says it has
 * expired, and a person who never asked reads what asking would give them.
 *
 * **What the file holds is read from what is wired.** The chapters are what the archive is assembled from
 * (ArchiveChapterInterface), so a kind of fact this provider comes to hold about a person is named on this
 * page by being wired, and this page is not edited.
 */
final readonly class ArchivePage
{
    /**
     * This person never asked for one.
     */
    public const string NEVER = 'never';

    /**
     * They asked and the document is not written yet.
     */
    public const string BEING_BUILT = 'being_built';

    public const string READY = 'ready';

    /**
     * It was kept for as long as an archive is kept and is gone, or is about to be: a row past its date is
     * nothing to this page, whether or not the timed step has come round yet.
     */
    public const string EXPIRED = 'expired';

    /**
     * @param iterable<ArchiveChapterInterface> $chapters in the order they are wired, which is the order
     *                                                    the document holds them
     */
    public function __construct(
        private PersonalArchiveRepositoryInterface $archives,
        private iterable $chapters,
        private ClockInterface $clock,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user): Response
    {
        $now = $this->clock->now();
        $archive = $this->archives->latestOf($user);
        $chapters = [];
        foreach ($this->chapters as $chapter) {
            $chapters[] = $chapter->name();
        }

        return $this->pages->render('account/archive.html.twig', [
            'user' => $user,
            'archive' => $archive,
            'state' => self::stateOf($archive, $now),
            'chapters' => $chapters,
            'kept_for_days' => PersonalArchive::KEPT_FOR_DAYS,
        ]);
    }

    private static function stateOf(?PersonalArchive $archive, DateTimeImmutable $now): string
    {
        if ($archive === null) {
            return self::NEVER;
        }
        if ($archive->hasExpired($now)) {
            return self::EXPIRED;
        }

        return $archive->isReady() ? self::READY : self::BEING_BUILT;
    }
}
