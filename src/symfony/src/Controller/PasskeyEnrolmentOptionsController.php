<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PasskeyOptionsStore;
use Heidi\Core\Application\Passkey\PasskeyEnrolment;
use Heidi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The options a browser creates a passkey with for the signed-in user (WebAuthn Level 3 §5.4,
 * architecture §5.2): drawn by the enrolment of the core, kept in the session of this browser for the
 * attestation that comes back.
 */
#[AsController]
final readonly class PasskeyEnrolmentOptionsController
{
    public const string ROUTE = 'heidi_interaction_account_passkeys_options';

    public function __construct(
        private AccountAccess $account,
        private PasskeyEnrolment $enrolment,
        private WebauthnCeremonies $ceremonies,
        private PasskeyOptionsStore $options,
    ) {
    }

    #[Route('/account/passkeys/options', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->signedIn($request);
        if ($session === null) {
            return new JsonResponse([
                'error' => InteractionPages::LOGIN_REQUIRED,
            ], Response::HTTP_UNAUTHORIZED, InteractionPages::HEADERS);
        }
        $options = $this->enrolment->begin($session->user);
        $this->options->storeCreation($request->getSession(), $session->user->id, $options);

        return new Response($this->ceremonies->optionsToJson($options), Response::HTTP_OK, [
            'Content-Type' => 'application/json',
            ...InteractionPages::HEADERS,
        ]);
    }
}
