<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Decision;

use Beffroi\Bundle\Controller\LoginController;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The user has to authenticate: the browser goes to the login page of this interaction, which resumes
 * it once the login is done (OIDC Core §3.1.2.1).
 */
final readonly class LoginRequiredRenderer implements DecisionRendererInterface
{
    public const string ROUTE = LoginController::ROUTE;

    public function __construct(
        private InteractionPage $page,
    ) {
    }

    public function decision(): string
    {
        return 'login';
    }

    public function render(Request $request, AuthorizationDecision $decision): Response
    {
        return $this->page->of($request, $decision->interaction, self::ROUTE);
    }
}
