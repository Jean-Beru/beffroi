<?php

declare(strict_types=1);

namespace Heidi\Bundle\Fido\Conformance;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Passkey\PasskeyEnrolment;
use Heidi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Heidi\Core\Exception\CredentialEnrolmentFailedException;
use Heidi\Core\Exception\PasskeyCeremonyFailedException;
use Heidi\Core\Port\UserRepositoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * "/attestation/result" of the FIDO2 server API (ServerAuthenticatorAttestationResponse): the response of
 * the tools, verified by the enrolment of the core against the options drawn for the challenge it
 * carries, the passkey saved to the user those options were drawn for, under the name of the tools.
 */
#[AsController]
final readonly class AttestationResultController
{
    public const string ROUTE = 'heidi_fido_conformance_attestation_result';

    /**
     * What every passkey of the tools is called (PasskeyCredential::NAME_MAX_LENGTH).
     */
    public const string PASSKEY_NAME = 'FIDO conformance tools';

    public function __construct(
        private TenantProvider $tenants,
        private UserRepositoryInterface $users,
        private RequestContextFactory $contexts,
        private PasskeyEnrolment $enrolment,
        private WebauthnCeremonies $ceremonies,
        private CeremonyStore $store,
    ) {
    }

    #[Route('/attestation/result', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $response = $request->getContent();
        try {
            $challenge = $this->ceremonies->credentialFromJson($response)
                ->response->clientDataJSON->challenge;
        } catch (PasskeyCeremonyFailedException $exception) {
            return ServerResponse::failed($exception->getMessage());
        }
        $ceremony = $this->store->takeCreation($challenge);
        if ($ceremony === null) {
            return ServerResponse::failed('No creation options were drawn with this challenge, or they were answered already.');
        }
        [$userId, $options] = $ceremony;
        $user = $this->users->find($userId);
        if ($user === null || ! $user->tenant->equals($this->tenants->provide())) {
            return ServerResponse::failed('The user the options were drawn for is gone.');
        }
        try {
            $this->enrolment->complete($user, self::PASSKEY_NAME, $options, $response, $this->contexts->fromRequest($request));
        } catch (CredentialEnrolmentFailedException $exception) {
            return ServerResponse::failed($exception->getMessage());
        }

        return ServerResponse::ok();
    }
}
