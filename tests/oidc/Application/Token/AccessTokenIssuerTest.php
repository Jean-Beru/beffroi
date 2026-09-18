<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Token\AccessTokenIssuer;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AccessTokenIssuerTest extends TestCase
{
    private AuthenticationSession $session;

    private FakeAccessTokenIssuer $jwt;

    private FakeAccessTokenIssuer $opaque;

    private AccessTokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->jwt = new FakeAccessTokenIssuer();
        $this->opaque = new FakeAccessTokenIssuer();
        $this->issuer = new AccessTokenIssuer([
            'jwt' => $this->jwt,
            'opaque' => $this->opaque,
        ]);
    }

    /**
     * Architecture §4.6: the registration of the client picks the issuer, and that one alone mints.
     */
    #[Test]
    public function aClientRegisteredForJwtGetsItsTokenFromTheJwtIssuer(): void
    {
        // Given
        $authorization = $this->authorization(AccessTokenFormat::Jwt);

        // When
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $this->jwt->issued);
        static::assertSame([], $this->opaque->issued);
        static::assertStringStartsWith('at:oidc-demo:', $token->value);
    }

    #[Test]
    public function aClientRegisteredForOpaqueTokensGetsItsTokenFromTheOpaqueIssuer(): void
    {
        // Given
        $authorization = $this->authorization(AccessTokenFormat::Opaque);

        // When
        $token = $this->issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $this->opaque->issued);
        static::assertSame([], $this->jwt->issued);
        static::assertStringStartsWith('at:oidc-demo:', $token->value);
    }

    /**
     * A client registered without a format gets the self-contained token, what spike 1 issued.
     */
    #[Test]
    public function aClientWithoutAFormatGetsAJwt(): void
    {
        // Given
        $authorization = GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', Clients::public($this->session->tenant), $this->session, Fixtures::now()));

        // When
        $this->issuer->issue($authorization, Fixtures::now());

        // Then
        static::assertSame([$authorization], $this->jwt->issued);
    }

    /**
     * A format without an issuer would fail at the first token of a client registered for it; it fails
     * when the issuer is built instead.
     */
    #[Test]
    public function everyFormatNeedsAnIssuer(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('No issuer writes access tokens in the "opaque" format.');

        // When
        new AccessTokenIssuer([
            'jwt' => $this->jwt,
        ]);
    }

    #[Test]
    public function anIssuerOfAnUnknownFormatIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('"paseto" is not an access token format; the formats are jwt, opaque.');

        // When
        new AccessTokenIssuer([
            'jwt' => $this->jwt,
            'opaque' => $this->opaque,
            'paseto' => new FakeAccessTokenIssuer(),
        ]);
    }

    private function authorization(AccessTokenFormat $format): GrantedAuthorization
    {
        $client = Clients::confidential($this->session->tenant, new FakePasswordHasher()->hash(Clients::SECRET), accessTokenFormat: $format);

        return GrantedAuthorization::fromAuthorizationCode(Tokens::code('the-code', $client, $this->session, Fixtures::now()));
    }
}
