<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\ResponseMode;

use function array_any;
use function array_keys;
use Heidi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Heidi\Oidc\Domain\Authorization\ResponseModeNames;
use Heidi\Oidc\Port\ServedResponseModesInterface;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Response;

/**
 * The ways of answering the authorization endpoint is wired with, one per response mode (architecture
 * §4.3): the single source the parser, the discovery document and the retirement of a signing key read, so
 * that a mode the provider announces is a mode it can render and no other is accepted (issue #98).
 *
 * It knows no mode of its own. Each way of answering names itself and declares what it does beside
 * delivering by the interfaces it implements, so a mode the provider gains is a class tagged here and
 * nothing edited: no enumeration of modes exists to add a case to.
 */
final readonly class AuthorizationResponseRenderers implements ServedResponseModesInterface
{
    /**
     * @var non-empty-array<non-empty-string, AuthorizationResponseRendererInterface>
     */
    private array $renderers;

    /**
     * @param iterable<AuthorizationResponseRendererInterface> $renderers at least one
     *
     * @throws LogicException when the wiring does not hold together
     */
    public function __construct(iterable $renderers)
    {
        $byMode = [];
        foreach ($renderers as $renderer) {
            $mode = $renderer->mode();
            if (isset($byMode[$mode])) {
                throw new LogicException(sprintf('Two ways of answering the authorization endpoint answer in the "%s" response mode.', $mode));
            }
            if ($mode === ResponseModeNames::ALIAS) {
                throw new LogicException(sprintf(
                    'The "%s" response mode delivers nothing of its own and names the signed mode a response type defaults to (JARM section 2.1); a way of answering declares AnswersTheJwtAliasInterface instead of taking that name.',
                    ResponseModeNames::ALIAS,
                ));
            }
            $byMode[$mode] = $renderer;
        }
        if ($byMode === []) {
            throw new LogicException('The authorization endpoint answers in at least one response mode.');
        }
        $this->renderers = $byMode;
    }

    public function servedResponseModes(): array
    {
        /** @var non-empty-list<non-empty-string> $modes */
        $modes = array_keys($this->renderers);

        return $modes;
    }

    public function responseModeNamed(string $requested): ?string
    {
        if ($requested === ResponseModeNames::ALIAS) {
            return $this->aliased()?->mode();
        }

        return isset($this->renderers[$requested]) ? $requested : null;
    }

    public function signsAnyAnswer(): bool
    {
        return array_any($this->renderers, static fn (AuthorizationResponseRendererInterface $renderer): bool => $renderer instanceof SignsTheAnswerInterface);
    }

    /**
     * @throws LogicException when no renderer answers in that mode, which the parser makes unreachable
     */
    public function render(string $mode, AuthorizationAnswer $answer): Response
    {
        $renderer = $this->renderers[$mode] ?? throw new LogicException(sprintf('No renderer answers in the "%s" response mode.', $mode));

        return $renderer->render($answer);
    }

    /**
     * JARM §2.1: the way of answering the alias resolves to, null when the wiring has none. A wiring where
     * two of them answer it has two answers to one question and is refused here, where the wiring is
     * collected.
     *
     * @throws LogicException
     */
    private function aliased(): ?AnswersTheJwtAliasInterface
    {
        $aliased = null;
        foreach ($this->renderers as $renderer) {
            if (! $renderer instanceof AnswersTheJwtAliasInterface) {
                continue;
            }
            if ($aliased !== null) {
                throw new LogicException(sprintf(
                    'The "%s" and "%s" response modes both answer "%s", and the alias names one signed mode (JARM section 2.1).',
                    $aliased->mode(),
                    $renderer->mode(),
                    ResponseModeNames::ALIAS,
                ));
            }
            $aliased = $renderer;
        }

        return $aliased;
    }
}
