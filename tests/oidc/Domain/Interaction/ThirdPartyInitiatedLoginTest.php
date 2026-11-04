<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Interaction;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\InitiateLoginUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Interaction\ThirdPartyInitiatedLogin;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §4
 */
final class ThirdPartyInitiatedLoginTest extends TestCase
{
    /**
     * OIDC Core §4
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
     * OIDC Core §4, §8
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
     * OIDC Core §4
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
     * RFC 3986 §2.1, §3.4
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
