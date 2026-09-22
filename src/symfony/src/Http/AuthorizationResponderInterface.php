<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Oidc\Domain\Authorization\RedirectTarget;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * What the pages of the authorization plane answer with, whatever the decision was (architecture §4.3,
 * §5.2): where the browser goes next, or what goes back to the client. The controllers see this and not
 * the class behind it, so that an integration can watch every decision of the endpoint without any of
 * them knowing it is watched.
 */
interface AuthorizationResponderInterface
{
    public function respond(Request $request, AuthorizationDecision $decision): Response;

    public function failure(Request $request, RedirectTarget $target, OAuth2Exception $exception, ?Interaction $interaction = null): Response;

    public function unresumable(Request $request, Interaction $interaction, InteractionExpiredException|InteractionCompletedException $exception): Response;

    public function unknownInteraction(): Response;
}
