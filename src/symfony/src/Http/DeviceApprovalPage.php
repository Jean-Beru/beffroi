<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Symfony\Component\HttpFoundation\Response;

/**
 * The one screen of the device flow (RFC 8628 §3.3, BCP 10027 §2), in its three states: the field where the
 * code is typed, the request that code names with what it asks for and where it came from, and the answer
 * once it is given. Rendered by the controller that shows it and by the one that comes back to it with what
 * went wrong.
 *
 * The request is named, not summarised: the provider that is asking, the client, the address the appliance
 * asked from and every scope it asked for, so that somebody who started nothing can tell that they started
 * nothing (BCP 10027 §2).
 */
final readonly class DeviceApprovalPage
{
    /**
     * The code names no request awaiting an answer: unknown, expired, already answered, already spent. One
     * message for the four, so that a code tried at random teaches nothing (RFC 8628 §5.1).
     */
    public const string UNKNOWN_CODE = 'unknown_code';

    /**
     * Too many codes were refused to this user in too little time (RFC 8628 §5.2, decision 0014).
     */
    public const string TOO_MANY_ATTEMPTS = 'too_many_attempts';

    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param string|null $refusal a code the template translates
     * @param string|null $shown the code as the appliance shows it (UserCode::shown()), so that a wrong
     *                          character can be corrected against the screen it was read from
     */
    public function renderForm(?string $refusal = null, ?string $shown = null, int $status = Response::HTTP_OK): Response
    {
        return $this->pages->render(
            'device.html.twig',
            [
                'refusal' => $refusal,
                'typed' => $shown,
            ],
            $status,
        );
    }

    /**
     * @param string $shown the code as the appliance shows it (UserCode::shown()), which is what the user
     *                     compares with the screen they read it from before allowing anything (BCP 10027 §2)
     */
    public function renderApproval(DeviceAuthorizationRecord $record, User $user, string $shown): Response
    {
        return $this->pages->render('device_approval.html.twig', [
            'record' => $record,
            'client' => $record->client,
            'tenant' => $record->tenant,
            'user' => $user,
            'scopes' => $record->scopes,
            'requested_from' => $record->requestedFrom,
            'typed' => $shown,
        ]);
    }

    public function renderAnswer(DeviceAuthorizationRecord $record): Response
    {
        return $this->pages->render('device_answered.html.twig', [
            'record' => $record,
            'client' => $record->client,
            'approved' => $record->isApproved(),
        ]);
    }
}
