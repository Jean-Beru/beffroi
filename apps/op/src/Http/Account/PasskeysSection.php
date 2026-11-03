<?php

declare(strict_types=1);

namespace App\Http\Account;

use function count;
use App\Controller\AccountPasskeysController;
use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;

/**
 * The passkeys of the account, on the home page: how many of them still sign the user in. A revoked one is
 * on the page of the passkeys, where its date is, and is counted nowhere; which ones are left is the
 * question ActiveCredentials answers, here as at every login.
 */
final readonly class PasskeysSection implements AccountSectionInterface
{
    public function __construct(
        private ActiveCredentials $active,
    ) {
    }

    public function route(): string
    {
        return AccountPasskeysController::ROUTE;
    }

    public function title(): string
    {
        return 'passkeys.title';
    }

    public function state(User $user): AccountSectionState
    {
        return new AccountSectionState('account.passkeys.state', [
            'count' => count($this->active->of($user, PasskeyCredential::class)),
        ]);
    }
}
