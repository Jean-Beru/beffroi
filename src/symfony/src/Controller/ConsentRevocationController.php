<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use function array_find;
use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Oidc\Application\Consent\ConsentRevocation;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Port\ActiveConsentsInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * A consent of the signed-in user taken back from the page of the account (architecture §4.3, §5.2): the
 * client asks afresh at its next authorization request, and what it was issued under that consent goes
 * with it.
 *
 * The consent is named by an identifier of the user's own list, as a request waiting for an answer is
 * (PendingApprovalsController): somebody else's consent is not in it, so it is not takeable back, and
 * one already taken back is not either.
 */
#[AsController]
final readonly class ConsentRevocationController
{
    public const string ROUTE = 'heidi_interaction_account_consents_revoke';

    public const string CSRF_TOKEN_ID = 'heidi_consent_revoke';

    public function __construct(
        private AccountAccess $account,
        private ActiveConsentsInterface $consents,
        private ConsentRevocation $revocation,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private UrlGeneratorInterface $router,
    ) {
    }

    #[Route(
        '/account/consents/{id}/revoke',
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
        $consent = array_find(
            $this->consents->activeOf($session->user),
            static fn (Consent $consent): bool => $consent->id->toRfc4122() === $id,
        );
        if ($consent === null) {
            throw new NotFoundHttpException('No such consent.');
        }
        $this->revocation->revoke($consent, $this->contexts->fromRequest($request));

        return $this->pages->redirect($this->router->generate(AccountConsentsController::ROUTE));
    }
}
