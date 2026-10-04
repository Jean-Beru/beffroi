<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Archive\ArchivePassword;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ArchiveChapterInterface;
use Beffroi\Core\Port\ArchiveContainerInterface;
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
 *
 * **A file that is ready leaves in one of two forms** (issue #483): the plain document, which is what
 * article 20 asks for, or the same document in a container the passphrase of that person opens. Which
 * container that is, is read from what is wired too, so the page names no format.
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
     * What was typed was not a passphrase this provider wraps a file under (issue #483). Which rule it
     * missed is not said: the page asks for several words and says so before anything is typed.
     */
    public const string PASSPHRASE_REFUSED = 'passphrase_refused';

    /**
     * @param iterable<ArchiveChapterInterface> $chapters in the order they are wired, which is the order
     *                                                    the document holds them
     */
    public function __construct(
        private PersonalArchiveRepositoryInterface $archives,
        private iterable $chapters,
        private ArchiveContainerInterface $container,
        private ClockInterface $clock,
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param string|null $refusal what was refused of the form that asks for a wrapped file, read once out
     *                             of the session the redirection crossed (issue #481)
     */
    public function render(User $user, ?string $refusal = null): Response
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
            'refusal' => $refusal,
            // what the field asks for and what the file will be called, both read from the rule and from
            // the wiring rather than written on the page (issue #483)
            'passphrase_minimum' => ArchivePassword::MINIMUM_LENGTH,
            'container' => $this->container->extension(),
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
