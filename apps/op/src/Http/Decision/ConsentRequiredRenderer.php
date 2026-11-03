<?php

declare(strict_types=1);

namespace App\Http\Decision;

use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The user has to agree to what the client asks for: the browser goes to the consent page of this
 * interaction, which resumes it once the answer is given (architecture §4.3).
 */
final readonly class ConsentRequiredRenderer implements DecisionRendererInterface
{
    public const string ROUTE = 'beffroi_interaction_consent';

    public function __construct(
        private InteractionPage $page,
    ) {
    }

    public function decision(): string
    {
        return 'consent';
    }

    public function render(Request $request, AuthorizationDecision $decision): Response
    {
        return $this->page->of($request, $decision->interaction, self::ROUTE);
    }
}
