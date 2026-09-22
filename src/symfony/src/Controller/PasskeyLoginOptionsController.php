<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PasskeyOptionsStore;
use Heidi\Core\Application\Passkey\PasskeyAuthentication;
use Heidi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The options a browser on the login page of an interaction signs an assertion with (WebAuthn Level 3
 * §5.5, architecture §5.2): for a discoverable credential, no user named, no allow list, so that the
 * page reveals nothing about who has a passkey; drawn for this browser and kept in its session until the
 * assertion comes back.
 */
#[AsController]
final readonly class PasskeyLoginOptionsController
{
    public const string ROUTE = 'heidi_interaction_passkey_login_options';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private PasskeyAuthentication $authentication,
        private WebauthnCeremonies $ceremonies,
        private PasskeyOptionsStore $options,
    ) {
    }

    #[Route('/login/passkey/options', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $interaction = $this->browser->pending($request, $tenant, $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER));
        if ($interaction === null) {
            return new JsonResponse(
                [
                    'error' => AuthorizationResponder::UNKNOWN_INTERACTION,
                ],
                Response::HTTP_BAD_REQUEST,
                InteractionPages::HEADERS,
            );
        }
        $options = $this->authentication->requestOptions($tenant);
        $this->options->storeRequest($request->getSession(), $options);

        return new Response($this->ceremonies->optionsToJson($options), Response::HTTP_OK, [
            'Content-Type' => 'application/json',
            ...InteractionPages::HEADERS,
        ]);
    }
}
