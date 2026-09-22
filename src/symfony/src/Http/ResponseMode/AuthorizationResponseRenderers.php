<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\ResponseMode;

use function array_map;
use function array_values;
use Heidi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Port\ServedResponseModesInterface;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;

/**
 * The ways of answering the authorization endpoint is wired with, one per response mode (architecture
 * §4.3): the single source both the parser and the discovery document read, so that a mode the provider
 * announces is a mode it can render and no other is accepted (issue #98).
 */
final readonly class AuthorizationResponseRenderers implements ServedResponseModesInterface
{
    /**
     * @var non-empty-array<string, AuthorizationResponseRendererInterface>
     */
    private array $renderers;

    /**
     * @param iterable<AuthorizationResponseRendererInterface> $renderers at least one
     */
    public function __construct(iterable $renderers)
    {
        $byMode = [];
        foreach ($renderers as $renderer) {
            $byMode[$renderer->mode()->value] = $renderer;
        }
        if ($byMode === []) {
            throw new LogicException('The authorization endpoint answers in at least one response mode.');
        }
        $this->renderers = $byMode;
    }

    public function servedResponseModes(): array
    {
        return array_map(
            static fn (AuthorizationResponseRendererInterface $renderer): ResponseMode => $renderer->mode(),
            array_values($this->renderers),
        );
    }

    /**
     * @throws LogicException when no renderer answers in that mode, which the parser makes unreachable
     */
    public function render(ResponseMode $mode, AuthorizationAnswer $answer): Response
    {
        $renderer = $this->renderers[$mode->value] ?? throw new LogicException(sprintf('No renderer answers in the "%s" response mode.', $mode->value));

        return $renderer->render($answer);
    }
}
