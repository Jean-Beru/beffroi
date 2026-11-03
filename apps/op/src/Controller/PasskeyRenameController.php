<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use App\Http\WhatWasRefused;
use Beffroi\Core\Application\Credential\CredentialRenaming;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

/**
 * A passkey of the signed-in user named again from the page of the account (architecture §5.2): what tells
 * one of their passkeys from another is a name they wrote, so correcting it is their own act. Someone
 * else's passkey is not found.
 *
 * It answers with a redirection whether the name was written or refused (issue #481): a browser reloading
 * the page it comes back to does not say the same thing again, and what was refused crosses the
 * redirection in the session (WhatWasRefused).
 *
 * **A session alone reaches it** (ReachedOnTheSessionAloneInterface): a name is read by the person and by
 * nothing that signs anybody in, so renaming a passkey neither adds a way in nor takes one away.
 */
#[AsController]
final readonly class PasskeyRenameController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_passkeys_rename';

    public const string CSRF_TOKEN_ID = 'beffroi_passkey_rename';

    public const string NAME_PARAMETER = 'name';

    public const string INVALID_NAME = 'invalid_name';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private CredentialRepositoryInterface $credentials,
        private CredentialRenaming $renaming,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route(
        '/account/passkeys/{id}/name',
        name: self::ROUTE,
        methods: ['POST'],
        requirements: [
            'id' => '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        ],
    )]
    public function __invoke(Request $request, string $id): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $passkey = $this->credentials->find(Uuid::fromString($id));
        if (! $passkey instanceof PasskeyCredential || ! $passkey->user->id->equals($session->user->id)) {
            throw new NotFoundHttpException('No such passkey.');
        }

        try {
            $this->renaming->rename(
                $passkey,
                $request->request->getString(self::NAME_PARAMETER),
                $this->contexts->fromRequest($request),
            );
        } catch (InvalidArgumentException) {
            // what the name may be is the rule of the kind and it is read on the server: the page says
            // the same thing for a name nobody typed and for one longer than a passkey holds
            $this->refusals->keep($request, self::INVALID_NAME);
        }

        return $this->pages->afterTheForm(AccountPasskeysController::ROUTE);
    }
}
