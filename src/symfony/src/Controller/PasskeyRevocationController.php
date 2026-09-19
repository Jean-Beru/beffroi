<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Credential\CredentialRevocation;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Port\CredentialRepositoryInterface;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A passkey of the signed-in user revoked from the page of the account (architecture §5.2): it never
 * authenticates again and stays listed with its date. Someone else's passkey is not found. What becomes
 * of the sessions it opened is the caller's policy (§3.4): this one leaves them.
 */
#[AsController]
final readonly class PasskeyRevocationController
{
    public const string ROUTE = 'heidi_interaction_account_passkeys_revoke';

    public const string CSRF_TOKEN_ID = 'heidi_passkey_revoke';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private CredentialRepositoryInterface $credentials,
        private CredentialRevocation $revocation,
        private CsrfTokenManagerInterface $csrf,
        private InteractionPages $pages,
        private UrlGeneratorInterface $router,
    ) {
    }

    #[Route('/account/passkeys/{id}/revoke', name: self::ROUTE, methods: ['POST'], requirements: [
        'id' => '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    ])]
    public function __invoke(Request $request, string $id): Response
    {
        $session = $this->browser->authenticationSession($request, $this->tenants->provide());
        if ($session === null) {
            return $this->pages->error(Response::HTTP_UNAUTHORIZED, AccountPasskeysController::LOGIN_REQUIRED);
        }
        $token = $request->request->get('_token');
        if (! is_string($token) || ! $this->csrf->isTokenValid(new CsrfToken(self::CSRF_TOKEN_ID, $token))) {
            return $this->pages->error(Response::HTTP_FORBIDDEN, ConsentController::INVALID_CSRF_TOKEN);
        }
        $passkey = $this->credentials->find(Uuid::fromString($id));
        if (! $passkey instanceof PasskeyCredential || ! $passkey->user->id->equals($session->user->id)) {
            throw new NotFoundHttpException('No such passkey.');
        }
        $this->revocation->revoke($passkey, $this->contexts->fromRequest($request));

        return $this->pages->redirect($this->router->generate(AccountPasskeysController::ROUTE));
    }
}
