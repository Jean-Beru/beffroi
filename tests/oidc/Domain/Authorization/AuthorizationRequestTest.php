<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §4.2: the validated request answers the questions the interaction asks (scope, prompt)
 * and knows where an error raised later goes; the response mode is query.
 */
final class AuthorizationRequestTest extends TestCase
{
    private Client $client;

    private RedirectUri $redirectUri;

    private AuthorizationRequest $request;

    protected function setUp(): void
    {
        $this->client = Clients::public(Fixtures::tenant());
        $this->redirectUri = new RedirectUri('https://spa.example/callback');
        $this->request = new AuthorizationRequest(
            $this->client,
            $this->redirectUri,
            new Scopes([Scope::openid(), new Scope('profile')]),
            new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', new Sha256CodeChallengeMethod()),
            'af0ifjsldkj',
            'n-0S6_WzA2Mj',
            [Prompt::Login],
        );
    }

    #[Test]
    public function itKnowsTheScopesItAsksFor(): void
    {
        // When / Then
        static::assertTrue($this->request->scopes->has(new Scope('profile')));
        static::assertFalse($this->request->scopes->has(new Scope('email')));
    }

    #[Test]
    public function itKnowsThePromptsItAsksFor(): void
    {
        // When / Then
        static::assertTrue($this->request->hasPrompt(Prompt::Login));
        static::assertFalse($this->request->hasPrompt(Prompt::None));
    }

    #[Test]
    public function itsResponseModeIsQuery(): void
    {
        // When / Then
        static::assertSame('query', $this->request->responseMode);
    }

    #[Test]
    public function itHasNoMaxAgeAndNoClaimsUnlessGiven(): void
    {
        // When / Then
        static::assertNull($this->request->maxAge);
        static::assertNull($this->request->claims);
    }

    #[Test]
    public function itKnowsWhereALaterErrorGoes(): void
    {
        // When
        $target = $this->request->redirectTarget();

        // Then
        static::assertSame($this->client, $target->client);
        static::assertSame($this->redirectUri, $target->redirectUri);
        static::assertSame('af0ifjsldkj', $target->state);
    }
}
