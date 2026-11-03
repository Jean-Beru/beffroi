<?php

declare(strict_types=1);

namespace App\MessageHandler;

use Beffroi\Core\Application\Archive\ArchiveAssembly;
use Beffroi\Core\Domain\Event\PersonAskedForTheirArchive;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * The archive of a person built off the request that asked for it (issue #453), on the lane the events
 * already travel.
 *
 * **The act is the message.** A person asking is an event of the core, so what builds the archive listens
 * for it and the page that was clicked dispatches nothing of its own: the request writes a row, says what
 * happened and answers, which is the issue's first condition and not a shape chosen here. A person who
 * asks twice while one is being built raises no second event, so a held button is not a second build.
 *
 * The tenant is the one of this process, as it is for every timed step: an archive exists because somebody
 * signed in to ask for it, and that somebody signed in here.
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class BuildThePersonalArchiveHandler
{
    public function __construct(
        private ArchiveAssembly $assembly,
    ) {
    }

    public function __invoke(PersonAskedForTheirArchive $event): void
    {
        $this->assembly->assemble($event->tenant, $event->archiveId);
    }
}
