<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Decision;

use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Sending the browser to a page of the interaction it began: the interaction is remembered in the
 * session of that browser and the page is named by its route, carrying the identifier the page reads
 * back. Every decision answered by a page does this and differs only in which page.
 */
final readonly class InteractionPage
{
    public function __construct(
        private InteractionPages $pages,
        private BrowserSession $browser,
        private UrlGeneratorInterface $router,
    ) {
    }

    public function of(Request $request, Interaction $interaction, string $route): Response
    {
        $this->browser->begin($request->getSession(), $interaction);

        return $this->pages->redirect($this->router->generate($route, [
            AuthorizationResponder::INTERACTION_PARAMETER => $interaction->id,
        ]));
    }
}
