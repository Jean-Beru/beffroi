<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthorizationRequestTest extends TestCase
{
    /**
     * Architecture §4.2: the validated request answers the questions the interaction asks (scope, prompt)
     * and knows where an error raised later goes; the response mode is query.
     */
    #[Test]
    public function itAnswersTheQuestionsOfTheInteraction(): void
    {
        $client = Clients::public(Fixtures::tenant());
        $redirectUri = new RedirectUri('https://spa.example/callback');
        $request = new AuthorizationRequest(
            $client,
            $redirectUri,
            [Scope::openid(), new Scope('profile')],
            new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', CodeChallengeMethod::S256),
            'af0ifjsldkj',
            'n-0S6_WzA2Mj',
            [Prompt::Login],
        );

        static::assertTrue($request->hasScope(new Scope('profile')));
        static::assertFalse($request->hasScope(new Scope('email')));
        static::assertTrue($request->hasPrompt(Prompt::Login));
        static::assertFalse($request->hasPrompt(Prompt::None));
        static::assertSame('query', $request->responseMode->value);
        static::assertNull($request->maxAge);
        static::assertNull($request->claims);

        $target = $request->redirectTarget();
        static::assertSame($client, $target->client);
        static::assertSame($redirectUri, $target->redirectUri);
        static::assertSame('af0ifjsldkj', $target->state);
    }
}
