<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http\ResponseMode;

use Beffroi\Bundle\Http\ResponseMode\AuthorizationResponseRenderers;
use Beffroi\Bundle\Tests\Functional\ResponseMode\FakeAliasedRenderer;
use Beffroi\Bundle\Tests\Functional\ResponseMode\FakeResponseModeRenderer;
use Beffroi\Bundle\Tests\Functional\ResponseMode\FakeSigningRenderer;
use Beffroi\Oidc\Domain\Authorization\ResponseModeNames;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The ways of answering the authorization endpoint is wired with (issue #240): the one source the parser, the
 * discovery document and the retirement of a signing key read. It knows no mode of its own.
 */
final class AuthorizationResponseRenderersTest extends TestCase
{
    /**
     * Multiple Response Type Encoding Practices §2.1: the names the ways of answering give themselves, in the
     * order they are wired, the first being what a request the provider cannot answer as it asked falls
     * back to.
     */
    #[Test]
    public function itNamesTheModesItIsWiredWithInTheOrderTheyAreWired(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([
            new FakeResponseModeRenderer('form_post'),
            new FakeResponseModeRenderer('query'),
        ]);

        // When / Then
        static::assertSame(['form_post', 'query'], $renderers->servedResponseModes());
    }

    #[Test]
    public function aModeItIsWiredWithIsAnsweredInItself(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([new FakeResponseModeRenderer('query')]);

        // When / Then
        static::assertSame('query', $renderers->responseModeNamed('query'));
    }

    #[Test]
    public function aModeNothingWiredAnswersIsAnsweredInNothing(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([new FakeResponseModeRenderer('query')]);

        // When / Then
        static::assertNull($renderers->responseModeNamed('form_post'));
    }

    /**
     * JARM §2.1: the alias delivers nothing of its own, and what it names is the wired way of answering that
     * declares it.
     */
    #[Test]
    public function theAliasIsAnsweredInTheModeThatDeclaresItAnswersIt(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([
            new FakeResponseModeRenderer('query'),
            new FakeSigningRenderer('form_post.jwt'),
            new FakeAliasedRenderer('query.jwt'),
        ]);

        // When / Then
        static::assertSame('query.jwt', $renderers->responseModeNamed(ResponseModeNames::ALIAS));
    }

    /**
     * JARM §2.1: a deployment that wires no such way of answering serves no alias, whatever else it signs.
     */
    #[Test]
    public function theAliasIsAnsweredInNothingWhereNoModeDeclaresIt(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([
            new FakeResponseModeRenderer('query'),
            new FakeSigningRenderer('form_post.jwt'),
        ]);

        // When / Then
        static::assertNull($renderers->responseModeNamed(ResponseModeNames::ALIAS));
    }

    /**
     * JARM §2: what the document announces beside the modes, the algorithms it announces with them and the
     * retirement window of the key that signs one all read this.
     */
    #[Test]
    public function itSignsAnAnswerWhenAWiredModeSaysSo(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([new FakeResponseModeRenderer('query'), new FakeSigningRenderer('form_post.jwt')]);

        // When / Then
        static::assertTrue($renderers->signsAnyAnswer());
    }

    #[Test]
    public function itSignsNoAnswerWhereNoWiredModeSaysSo(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([new FakeResponseModeRenderer('query'), new FakeResponseModeRenderer('form_post')]);

        // When / Then
        static::assertFalse($renderers->signsAnyAnswer());
    }

    #[Test]
    public function itRefusesTwoWaysOfAnsweringInTheSameMode(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Two ways of answering the authorization endpoint answer in the "query" response mode.');

        // When
        new AuthorizationResponseRenderers([new FakeResponseModeRenderer('query'), new FakeResponseModeRenderer('query')]);
    }

    /**
     * JARM §2.1: the alias names a mode and is not one, so a way of answering that took its name would be a
     * delivery nothing could resolve.
     */
    #[Test]
    public function itRefusesAWayOfAnsweringThatTakesTheNameOfTheAlias(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('declares AnswersTheJwtAliasInterface instead of taking that name');

        // When
        new AuthorizationResponseRenderers([new FakeResponseModeRenderer(ResponseModeNames::ALIAS)]);
    }

    /**
     * JARM §2.1: the alias names one signed mode, so a wiring with two answers to that question is a wiring
     * that does not hold together.
     */
    #[Test]
    public function itRefusesTwoWaysOfAnsweringTheAlias(): void
    {
        // Given
        $renderers = new AuthorizationResponseRenderers([new FakeAliasedRenderer('query.jwt'), new FakeAliasedRenderer('form_post.jwt')]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('both answer "jwt", and the alias names one signed mode');

        // When
        $renderers->responseModeNamed(ResponseModeNames::ALIAS);
    }

    #[Test]
    public function itRefusesAnEndpointWiredWithNoWayOfAnswering(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The authorization endpoint answers in at least one response mode.');

        // When
        new AuthorizationResponseRenderers([]);
    }
}
