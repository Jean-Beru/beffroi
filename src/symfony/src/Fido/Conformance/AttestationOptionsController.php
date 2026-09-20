<?php

declare(strict_types=1);

namespace Heidi\Bundle\Fido\Conformance;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Core\Application\Passkey\PasskeyEnrolment;
use Heidi\Core\Bridge\Webauthn\WebauthnCeremonies;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialCreationOptions;

/**
 * "/attestation/options" of the FIDO2 server API (FIDO Conformance Tools,
 * ServerPublicKeyCredentialCreationOptionsRequest): the options the enrolment of the core draws for the
 * user the tools name, created on their first ceremony, with what the tools ask for and the product
 * never does (WebAuthn Level 3 §5.4: the attestation conveyance, the authenticator selection, the
 * extensions), kept by their challenge for the attestation that comes back.
 */
#[AsController]
final readonly class AttestationOptionsController
{
    public const string ROUTE = 'heidi_fido_conformance_attestation_options';

    public function __construct(
        private TenantProvider $tenants,
        private ConformanceUsers $users,
        private PasskeyEnrolment $enrolment,
        private WebauthnCeremonies $ceremonies,
        private CeremonyStore $store,
    ) {
    }

    #[Route('/attestation/options', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $body = ServerRequest::fromRequest($request);
            $user = $this->users->findOrCreate($this->tenants->provide(), $body->string('username'), $body->string('displayName'));
            $options = self::options($this->enrolment->begin($user), $body);
        } catch (InvalidArgumentException|InvalidDataException $exception) {
            return ServerResponse::failed($exception->getMessage());
        }
        $this->store->storeCreation($user->id, $options);

        return ServerResponse::options($this->ceremonies->optionsToJson($options));
    }

    /**
     * The options of the product (the relying party, the user entity with its handle, the challenge, the
     * algorithms, the passkeys excluded) with what the tools ask for.
     *
     * @throws ServerRequestException
     * @throws InvalidArgumentException
     * @throws InvalidDataException
     */
    private static function options(PublicKeyCredentialCreationOptions $product, ServerRequest $body): PublicKeyCredentialCreationOptions
    {
        $selection = $body->optionalObject('authenticatorSelection');
        $residentKey = $selection?->optionalString('residentKey');
        if ($residentKey === null && $selection?->optionalBool('requireResidentKey') === true) {
            $residentKey = AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED;
        }
        $extensions = [];
        foreach ($body->optionalObject('extensions')?->members() ?? [] as $name => $value) {
            $extensions[] = AuthenticationExtension::create($name, $value);
        }

        return PublicKeyCredentialCreationOptions::create(
            $product->rp,
            $product->user,
            $product->challenge,
            $product->pubKeyCredParams,
            AuthenticatorSelectionCriteria::create(
                $selection?->optionalString('authenticatorAttachment'),
                $selection?->optionalString('userVerification') ?? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
                $residentKey,
            ),
            $body->optionalString('attestation') ?? PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $product->excludeCredentials,
            CeremonyStore::LIFETIME * 1000,
            AuthenticationExtensions::create($extensions),
        );
    }
}
