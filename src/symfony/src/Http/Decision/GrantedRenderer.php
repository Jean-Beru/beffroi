<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Decision;

use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\ResponseMode\AuthorizationResponseRenderers;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Beffroi\Oidc\Domain\Interaction\Granted;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The code is issued: the interaction is over, the browser is no longer holding it, and the answer goes
 * back to the client in the response mode of its request (OIDC Core §3.1.2.5), which the renderer of
 * that mode shapes.
 */
final readonly class GrantedRenderer implements DecisionRendererInterface
{
    public function __construct(
        private BrowserSession $browser,
        private AuthorizationResponseRenderers $modes,
    ) {
    }

    public function decision(): string
    {
        return 'granted';
    }

    public function render(Request $request, AuthorizationDecision $decision): Response
    {
        if (! $decision instanceof Granted) {
            throw new LogicException(sprintf('A decision named "%s" is not the one this answers for.', $decision->name()));
        }
        $this->browser->forget($request->getSession(), $decision->interaction);

        return $this->modes->render(
            $decision->interaction->request->responseMode,
            new AuthorizationAnswer($decision->interaction->request->client, $decision->response->redirectUri, $decision->response->parameters()),
        );
    }
}
