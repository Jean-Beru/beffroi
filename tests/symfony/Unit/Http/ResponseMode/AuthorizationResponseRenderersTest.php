<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http\ResponseMode;

use App\Http\ResponseMode\AuthorizationResponseRenderers;
use App\Tests\Symfony\Functional\ResponseMode\FakeAliasedRenderer;
use App\Tests\Symfony\Functional\ResponseMode\FakeResponseModeRenderer;
use App\Tests\Symfony\Functional\ResponseMode\FakeSigningRenderer;
use Beffroi\Oidc\Domain\Authorization\ResponseModeNames;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthorizationResponseRenderersTest extends TestCase
{
    /**
     * Multiple Response Type Encoding Practices §2.1
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
     * JARM §2.1
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
     * JARM §2.1
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
     * JARM §2
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
     * JARM §2.1
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
     * JARM §2.1
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
