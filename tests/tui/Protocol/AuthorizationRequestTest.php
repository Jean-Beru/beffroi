<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Protocol\AuthorizationRequest;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use function array_diff_key;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The request of one sign-in: a code with PKCE S256, three values drawn for it alone, a phishing-resistant
 * proof made essential, and a fresh login.
 */
final class AuthorizationRequestTest extends TestCase
{
    /**
     * RFC 7636 Appendix B.
     */
    #[Test]
    public function theChallengeIsTheS256OfTheVerifier(): void
    {
        // When / Then
        static::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', AuthorizationRequest::s256('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
    }

    /**
     * FAPI 2.0 Security Profile §5.3.3.2, item 4: a new challenge for every request, and so a new state and a new
     * nonce.
     */
    #[Test]
    public function everyRequestDrawsItsOwnValues(): void
    {
        // Given
        $first = AuthorizationRequest::draw(FakeProvider::CLIENT_ID, FakeProvider::REDIRECT_URI, 'en', FakeProvider::ADMINISTRATION);

        // When
        $second = AuthorizationRequest::draw(FakeProvider::CLIENT_ID, FakeProvider::REDIRECT_URI, 'en', FakeProvider::ADMINISTRATION);

        // Then
        static::assertSame(
            [false, false, false],
            [$first->state === $second->state, $first->nonce === $second->nonce, $first->codeVerifier === $second->codeVerifier],
        );
    }

    /**
     * OIDC Core §5.5.1.1 and decision 0038: the "acr" of a phishing-resistant proof is essential, and the name of the
     * administrator is asked of the ID token (§5.5), the access token being addressed to the administration API.
     */
    #[Test]
    public function thePhishingResistantClassIsEssentialAndTheNameIsAskedOfTheIdToken(): void
    {
        // Given
        $parameters = AuthorizationRequest::draw(FakeProvider::CLIENT_ID, FakeProvider::REDIRECT_URI, 'en', FakeProvider::ADMINISTRATION)->parameters();

        // When
        $claims = json_decode($parameters['claims'] ?? '', true, 8, JSON_THROW_ON_ERROR);

        // Then
        static::assertSame(['id_token' => ['acr' => ['essential' => true, 'values' => ['phr']], 'name' => null, 'preferred_username' => null]], $claims);
    }

    /**
     * RFC 8707 §2.1, decision 0038: the tokens are asked for the administration API, which the provider hands out to
     * an administrator of the tenant alone; a person who is not one is denied the request.
     */
    #[Test]
    public function theTokensAreAskedForTheAdministrationApi(): void
    {
        // When
        $parameters = AuthorizationRequest::draw(FakeProvider::CLIENT_ID, FakeProvider::REDIRECT_URI, 'en', FakeProvider::ADMINISTRATION)->parameters();

        // Then
        static::assertSame(FakeProvider::ADMINISTRATION, $parameters['resource'] ?? null);
    }

    /**
     * RFC 6749 §4.1.1, RFC 7636 §4.3, OIDC Core §3.1.2.1.
     */
    #[Test]
    public function theRequestIsACodeWithPkceAFreshLoginAndTheLanguageOfTheTerminal(): void
    {
        // Given
        $request = AuthorizationRequest::draw(FakeProvider::CLIENT_ID, FakeProvider::REDIRECT_URI, 'fr', FakeProvider::ADMINISTRATION);

        // When
        $parameters = $request->parameters();

        // Then
        static::assertSame(
            [
                'response_type' => 'code',
                'client_id' => FakeProvider::CLIENT_ID,
                'redirect_uri' => FakeProvider::REDIRECT_URI,
                'scope' => 'openid profile',
                'state' => $request->state,
                'nonce' => $request->nonce,
                'code_challenge' => $request->codeChallenge(),
                'code_challenge_method' => 'S256',
                'prompt' => 'login',
                'ui_locales' => 'fr',
                'resource' => FakeProvider::ADMINISTRATION,
            ],
            array_diff_key($parameters, ['claims' => true]),
        );
    }
}
