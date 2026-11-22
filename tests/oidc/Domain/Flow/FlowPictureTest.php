<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class FlowPictureTest extends TestCase
{
    #[Test]
    public function theActorsAreTheOnesItsHopsSpeakTo(): void
    {
        // Given
        $picture = new FlowPicture(Grants::clientCredentials(), [
            new Hop(Actor::Client, Actor::Provider, 'token_request', 'RFC 6749 §4.4.2'),
            new Hop(Actor::Provider, Actor::Client, 'token_response', 'RFC 6749 §4.4.3'),
        ]);

        // When
        $actors = $picture->actors();

        // Then
        static::assertSame([Actor::Client, Actor::Provider], $actors);
    }

    #[Test]
    public function theActorsAreInTheOrderTheDrawingDeclaresThem(): void
    {
        // Given
        $picture = new FlowPicture(Grants::authorizationCode(), [
            new Hop(Actor::ResourceServer, Actor::Provider, 'introspection_request', 'RFC 7662 §2.1'),
            new Hop(Actor::Browser, Actor::Provider, 'authorization_request', 'RFC 6749 §4.1.1'),
            new Hop(Actor::Client, Actor::Provider, 'token_request', 'RFC 6749 §4.1.3'),
        ]);

        // When
        $actors = $picture->actors();

        // Then
        static::assertSame([Actor::Browser, Actor::Client, Actor::Provider, Actor::ResourceServer], $actors);
    }

    #[Test]
    public function itNamesTheHopsItDraws(): void
    {
        // Given
        $picture = new FlowPicture(Grants::clientCredentials(), [
            new Hop(Actor::Client, Actor::Provider, 'token_request', 'RFC 6749 §4.4.2'),
        ]);

        // When / Then
        static::assertTrue($picture->draws('token_request'));
        static::assertFalse($picture->draws('authorization_request'));
    }

    #[Test]
    public function aFlowWithoutAHopIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The flow of "client_credentials" is drawn with at least one hop.');

        // When
        new FlowPicture(Grants::clientCredentials(), []); // @phpstan-ignore argument.type (the contract is broken on purpose)
    }
}
