<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Interaction;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\InitiateLoginUri;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Interaction\ThirdPartyInitiatedLogin;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §4: where a browser goes when this provider begins a login at a client, and what the
 * redirection carries.
 */
final class ThirdPartyInitiatedLoginTest extends TestCase
{
    /**
     * OIDC Core §4: "iss" is what tells the client which provider to have its user authenticate against,
     * and it is the one member the redirection always carries.
     */
    #[Test]
    public function itSendsTheBrowserToTheUriTheClientRegisteredNamingThisProvider(): void
    {
        // Given
        $login = new ThirdPartyInitiatedLogin(
            new InitiateLoginUri('https://rp.example/start'),
            Fixtures::tenant()->issuer,
        );

        // When / Then
        static::assertSame('https://rp.example/start?iss=https%3A%2F%2Fid.acme.example', $login->location());
    }

    /**
     * A browser that holds no session says nothing of whom to sign in, and a caller that named no landing
     * page asks for none: the redirection is the issuer and nothing else.
     */
    #[Test]
    public function aLoginNobodyIsSignedInForCarriesTheIssuerAlone(): void
    {
        // Given
        $login = new ThirdPartyInitiatedLogin(
            new InitiateLoginUri('https://rp.example/start'),
            Fixtures::tenant()->issuer,
        );

        // When / Then
        static::assertSame(['iss' => 'https://id.acme.example'], $login->parameters);
    }

    /**
     * OIDC Core §4 and §8: the hint names the user as that client sees them, so a client assigned a
     * pairwise identifier is hinted with that one and never with the identifier the core keeps.
     */
    #[Test]
    public function theHintNamesTheUserAsThatClientSeesThem(): void
    {
        // Given
        $login = new ThirdPartyInitiatedLogin(
            new InitiateLoginUri('https://rp.example/start'),
            Fixtures::tenant()->issuer,
            new Subject('the-one-this-client-was-handed'),
        );

        // When / Then
        static::assertSame('the-one-this-client-was-handed', $login->parameters['login_hint']);
    }

    /**
     * OIDC Core §4: where the client is asked to land the user once it has signed them in. It is an
     * object the client registered and never a string of a request, which is what keeps this route from
     * being a redirector with a landing page of the caller's choosing.
     */
    #[Test]
    public function theLandingPageIsOneTheClientRegistered(): void
    {
        // Given
        $login = new ThirdPartyInitiatedLogin(
            new InitiateLoginUri('https://rp.example/start'),
            Fixtures::tenant()->issuer,
            null,
            new RedirectUri('https://rp.example/callback'),
        );

        // When / Then
        static::assertSame('https://rp.example/callback', $login->parameters['target_link_uri']);
    }

    /**
     * RFC 3986 §2.1 and §3.4: the query the client registered is kept, and what §4 adds is added to it.
     * A client that registered a URI with a query of its own is sent to the URI it registered.
     */
    #[Test]
    public function aRegisteredQueryIsKeptAndTheMembersAreAddedToIt(): void
    {
        // Given
        $login = new ThirdPartyInitiatedLogin(
            new InitiateLoginUri('https://rp.example/start?tenant=acme'),
            Fixtures::tenant()->issuer,
            null,
            new RedirectUri('https://rp.example/callback'),
        );

        // When / Then
        static::assertSame(
            'https://rp.example/start?tenant=acme&iss=https%3A%2F%2Fid.acme.example&target_link_uri=https%3A%2F%2Frp.example%2Fcallback',
            $login->location(),
        );
    }
}
