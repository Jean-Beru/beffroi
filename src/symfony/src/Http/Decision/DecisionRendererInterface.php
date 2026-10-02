<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Decision;

use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * How this integration answers one decision of the authorization endpoint (architecture §4.3, §5.2).
 * A decision the provider gains is a class here and a line in the wiring; nothing enumerates the
 * decisions and nothing reads a class name to tell them apart.
 */
interface DecisionRendererInterface
{
    /**
     * The decision this answers for, as the decision names itself.
     *
     * @return non-empty-string
     */
    public function decision(): string;

    public function render(Request $request, AuthorizationDecision $decision): Response;
}
