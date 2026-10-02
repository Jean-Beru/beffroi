<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Fido\Conformance;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Core\Application\Passkey\PasskeyAuthentication;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * "/assertion/options" of the FIDO2 server API (ServerPublicKeyCredentialGetOptionsRequest): the options
 * the authentication of the core draws for the user the tools name (WebAuthn Level 3 §5.5: their
 * passkeys allowed), with the user verification and the extensions the tools ask for, kept by their
 * challenge for the assertion that comes back.
 */
#[AsController]
final readonly class AssertionOptionsController
{
    public const string ROUTE = 'beffroi_fido_conformance_assertion_options';

    public function __construct(
        private TenantProvider $tenants,
        private ConformanceUsers $users,
        private PasskeyAuthentication $authentication,
        private WebauthnCeremonies $ceremonies,
        private CeremonyStore $store,
    ) {
    }

    #[Route('/assertion/options', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        try {
            $body = ServerRequest::fromRequest($request);
            $user = $this->users->find($tenant, $body->string('username'));
            if ($user === null) {
                return ServerResponse::failed('This user is unknown.');
            }
            $options = self::options($this->authentication->requestOptions($tenant, $user), $body);
        } catch (InvalidArgumentException|InvalidDataException $exception) {
            return ServerResponse::failed($exception->getMessage());
        }
        $this->store->storeRequest($options);

        return ServerResponse::options($this->ceremonies->optionsToJson($options));
    }

    /**
     * The options of the product (the challenge, the relying party, the passkeys allowed) with what the
     * tools ask for.
     *
     * @throws ServerRequestException
     * @throws InvalidDataException
     */
    private static function options(PublicKeyCredentialRequestOptions $product, ServerRequest $body): PublicKeyCredentialRequestOptions
    {
        $extensions = [];
        foreach ($body->optionalObject('extensions')?->members() ?? [] as $name => $value) {
            $extensions[] = AuthenticationExtension::create($name, $value);
        }

        return PublicKeyCredentialRequestOptions::create(
            $product->challenge,
            $product->rpId,
            $product->allowCredentials,
            $body->optionalString('userVerification') ?? PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            CeremonyStore::LIFETIME * 1000,
            AuthenticationExtensions::create($extensions),
        );
    }
}
