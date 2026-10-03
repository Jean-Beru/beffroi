<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A session of the signed-in user ended from the page of the account (architecture §5.2): it authenticates
 * nothing afterwards, and what it opened for a relying party is reached by the back-channel exactly as a
 * logout reaches it, because the end of a session is one act of the core and says so once
 * (AuthenticationSessionEnded). Someone else's session is not found.
 *
 * Ending the session of the browser reading the page is not the same act as ending another: that browser
 * is signed out here, the way the end session endpoint signs one out, and it is told so.
 */
#[AsController]
final readonly class AccountSessionRevocationController
{
    public const string ROUTE = 'beffroi_interaction_account_sessions_revoke';

    public const string CSRF_TOKEN_ID = 'beffroi_session_revoke';

    public function __construct(
        private AccountAccess $account,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionTerminator $terminator,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private UrlGeneratorInterface $router,
    ) {
    }

    #[Route(
        '/account/sessions/{id}/revoke',
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
        $ended = $this->sessions->find(Uuid::fromString($id));
        if (! $ended instanceof AuthenticationSession || ! $ended->user->id->equals($session->user->id) || $ended->hasEnded()) {
            throw new NotFoundHttpException('No such session.');
        }
        $this->terminator->end($ended, SessionEnd::User, $this->contexts->fromRequest($request));
        if (! $ended->id->equals($session->id)) {
            return $this->pages->redirect($this->router->generate(AccountSessionsController::ROUTE));
        }
        $this->browser->unbind($request->getSession());

        return $this->pages->render('logged_out.html.twig', ['logged_out' => true]);
    }
}
