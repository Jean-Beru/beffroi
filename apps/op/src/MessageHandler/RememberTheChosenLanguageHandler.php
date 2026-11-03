<?php

declare(strict_types=1);

namespace App\MessageHandler;

use App\Message\RememberTheChosenLanguage;
use Beffroi\Core\Application\Identity\LanguageRecording;
use Beffroi\Core\Port\UserRepositoryInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Writes on the account the language a person chose on a page (issue #471). Nothing of the request that
 * chose it waits for this: the cookie is what the next journey of that browser starts in and the
 * interaction is what the next page of this one is read in, so the claim is written on the lane.
 *
 * A person whose row is gone by the time this runs is nobody to write to, and the message is done: an
 * account deleted between the choice and the write is not a failure of the choice.
 */
#[AsMessageHandler]
final readonly class RememberTheChosenLanguageHandler
{
    public function __construct(
        private UserRepositoryInterface $users,
        private LanguageRecording $recording,
    ) {
    }

    public function __invoke(RememberTheChosenLanguage $command): void
    {
        $user = $this->users->find($command->user);
        if ($user === null) {
            return;
        }
        $this->recording->record($user, $command->locale);
    }
}
