<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\ResponseMode;

use Heidi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Symfony\Component\HttpFoundation\Response;

/**
 * One way of handing the answer of the authorization endpoint to the client (OAuth 2.0 Multiple Response
 * Type Encoding Practices §2.1). A mode the provider serves is a class tagged "heidi.response_mode", not
 * a branch added to a caller: what is tagged is what the parser accepts and what the discovery document
 * announces.
 */
interface AuthorizationResponseRendererInterface
{
    public function mode(): ResponseMode;

    public function render(AuthorizationAnswer $answer): Response;
}
