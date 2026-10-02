<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\ResponseMode;

use Beffroi\Bundle\Http\ResponseMode\AuthorizationResponseRendererInterface;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use function http_build_query;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #240: a way of answering the authorization endpoint the module knows nothing about, wired into this
 * kernel as a deployment would wire one. It names itself, and that name is what a request may ask for, what
 * the discovery document announces and what the endpoint answers in; no class of `src` names it anywhere.
 *
 * What it delivers is deliberately unlike the modes the bundle wires, a plain document carrying the
 * parameters, so that a test can tell it answered and not one of them.
 */
final readonly class InventedResponseModeRenderer implements AuthorizationResponseRendererInterface
{
    public const string MODE = 'invented';

    public const string CONTENT_TYPE = 'application/x-invented-response';

    public function mode(): string
    {
        return self::MODE;
    }

    public function render(AuthorizationAnswer $answer): Response
    {
        return new Response(http_build_query($answer->parameters), Response::HTTP_OK, [
            'Content-Type' => self::CONTENT_TYPE,
        ]);
    }
}
