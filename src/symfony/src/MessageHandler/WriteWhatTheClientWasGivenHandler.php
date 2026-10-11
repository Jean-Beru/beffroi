<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Oidc\Application\Disclosure\DisclosureRecording;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * What a client was given of a person, written beside the act that gave it (issue #590), on the lane the
 * events already travel: the register is never on the path of a token request, and a row that cannot be
 * written does not undo what was issued.
 *
 * It handles the one act that hands something over, where `WriteTheActDownHandler` beside it handles the
 * interface every act carries: a code is a reference its client exchanges and hands nothing over, and what
 * the two reads of a token take out is what the token already entitled whoever holds it to
 * (decision 0022).
 */
#[AsMessageHandler(bus: 'event.bus')]
final readonly class WriteWhatTheClientWasGivenHandler
{
    public function __construct(
        private DisclosureRecording $recording,
    ) {
    }

    public function __invoke(TokensIssued $event): void
    {
        $this->recording->record($event);
    }
}
