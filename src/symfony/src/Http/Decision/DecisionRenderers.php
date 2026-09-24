<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\Decision;

use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The ways this integration answers a decision, in the order they are wired: the one source of truth
 * over them. A decision nothing answers for is an integration wired without the renderer of a decision
 * the provider makes, which is a fault of the wiring and never of a request.
 */
final readonly class DecisionRenderers
{
    /**
     * @var array<string, DecisionRendererInterface> by the decision each one answers for
     */
    private array $renderers;

    /**
     * @param iterable<DecisionRendererInterface> $renderers
     *
     * @throws LogicException when two renderers answer for one decision
     */
    public function __construct(iterable $renderers)
    {
        $wired = [];
        foreach ($renderers as $renderer) {
            $decision = $renderer->decision();
            if (isset($wired[$decision])) {
                throw new LogicException(sprintf('Two renderers answer the decision "%s".', $decision));
            }
            $wired[$decision] = $renderer;
        }
        $this->renderers = $wired;
    }

    /**
     * @throws LogicException when nothing wired answers this decision
     */
    public function render(Request $request, AuthorizationDecision $decision): Response
    {
        $renderer = $this->renderers[$decision->name()] ?? throw new LogicException(sprintf(
            'The decision "%s" is not one this integration answers.',
            $decision->name(),
        ));

        return $renderer->render($request, $decision);
    }
}
