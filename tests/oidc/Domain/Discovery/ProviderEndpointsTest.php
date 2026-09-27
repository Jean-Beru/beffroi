<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Discovery;

use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ProviderEndpointsTest extends TestCase
{
    /**
     * OIDC Discovery §3: the endpoints are absolute URLs; a query is retained as it is (RFC 6749 §3.1).
     */
    #[Test]
    public function itKeepsAbsoluteHttpsUrlsAsTheyAre(): void
    {
        // When
        $endpoints = new ProviderEndpoints(
            'https://id.acme.example/authorize?tenant=acme',
            'https://id.acme.example/token',
            'https://id.acme.example/userinfo',
            'https://id.acme.example/jwks',
            'https://id.acme.example/logout',
            'https://id.acme.example/introspect',
            'https://id.acme.example/revoke',
            'https://id.acme.example/par',
            'https://id.acme.example/device_authorization',
            'https://id.acme.example/device',
            'https://id.acme.example/backchannel_authentication',
            'https://id.acme.example/account/approvals',
        );

        // Then
        static::assertSame('https://id.acme.example/authorize?tenant=acme', $endpoints->authorization);
        static::assertSame('https://id.acme.example/token', $endpoints->token);
        static::assertSame('https://id.acme.example/userinfo', $endpoints->userinfo);
        static::assertSame('https://id.acme.example/jwks', $endpoints->jwks);
        static::assertSame('https://id.acme.example/logout', $endpoints->endSession);
        static::assertSame('https://id.acme.example/introspect', $endpoints->introspection);
        static::assertSame('https://id.acme.example/revoke', $endpoints->revocation);
        static::assertSame('https://id.acme.example/par', $endpoints->pushedAuthorizationRequest);
        static::assertSame('https://id.acme.example/device_authorization', $endpoints->deviceAuthorization);
        static::assertSame('https://id.acme.example/device', $endpoints->deviceVerification);
        static::assertSame('https://id.acme.example/backchannel_authentication', $endpoints->backchannelAuthentication);
        static::assertSame('https://id.acme.example/account/approvals', $endpoints->backchannelApproval);
    }

    /**
     * RFC 6761 §6.3: plain HTTP is tolerated on a loopback host for development, the same exception the
     * issuer makes.
     */
    #[Test]
    public function itToleratesPlainHttpOnLoopback(): void
    {
        // When
        $endpoints = new ProviderEndpoints(
            'http://localhost:8000/authorize',
            'HTTPS://op.localhost/token',
            'http://OP.LOCALHOST/userinfo',
            'http://127.0.0.1/jwks',
            'http://[::1]/logout',
            'https://op.localhost/introspect',
            'https://op.localhost/revoke',
            'https://op.localhost/par',
            'https://op.localhost/device_authorization',
            'https://op.localhost/device',
            'https://op.localhost/backchannel_authentication',
            'https://op.localhost/account/approvals',
        );

        // Then
        static::assertSame('http://localhost:8000/authorize', $endpoints->authorization);
        static::assertSame('HTTPS://op.localhost/token', $endpoints->token);
        static::assertSame('http://OP.LOCALHOST/userinfo', $endpoints->userinfo);
    }

    /**
     * RFC 6749 §3.2 requires TLS on the token endpoint, and oidc_login refuses a token endpoint in clear
     * even on loopback; RFC 7662 §2.1 and RFC 7009 §2 require it of the two endpoints that take the
     * client credentials and a token the same way.
     */
    #[Test]
    #[DataProvider('provideEndpointsRequiringTls')]
    public function itRefusesAnEndpointThatCarriesCredentialsInClearEvenOnLoopback(string $name, int $position): void
    {
        // Given
        $urls = [
            'https://op.localhost/authorize',
            'https://op.localhost/token',
            'https://op.localhost/userinfo',
            'https://op.localhost/jwks',
            'https://op.localhost/logout',
            'https://op.localhost/introspect',
            'https://op.localhost/revoke',
            'https://op.localhost/par',
            'https://op.localhost/device_authorization',
            'https://op.localhost/device',
            'https://op.localhost/backchannel_authentication',
            'https://op.localhost/account/approvals',
        ];
        $urls[$position] = 'http://localhost/x';

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($name
        . ' endpoint "http://localhost/x" must use HTTPS (RFC 6749 section 3.2, RFC 9126 section 2, RFC 8628 section 3.1, CIBA Core section 7), on a loopback host too');

        // When
        new ProviderEndpoints(...$urls);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideEndpointsRequiringTls(): iterable
    {
        yield 'token' => ['token', 1];
        yield 'introspection' => ['introspection', 5];
        yield 'revocation' => ['revocation', 6];
        yield 'pushed authorization request' => ['pushed authorization request', 7];
        yield 'device authorization' => ['device authorization', 8];
        yield 'backchannel authentication' => ['backchannel authentication', 10];
    }

    /**
     * RFC 6749 §3.1, §3.2: absolute, no fragment, over TLS; what a relying party would use as it is must
     * be refused before it is announced.
     */
    #[Test]
    #[DataProvider('provideRefusedUrls')]
    public function itRefusesWhatARelyingPartyMustNotUse(string $url, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('The authorization endpoint "' . $url . '" ' . $reason);

        // When
        new ProviderEndpoints(
            $url,
            'https://id.acme.example/token',
            'https://id.acme.example/userinfo',
            'https://id.acme.example/jwks',
            'https://id.acme.example/logout',
            'https://id.acme.example/introspect',
            'https://id.acme.example/revoke',
            'https://id.acme.example/par',
            'https://id.acme.example/device_authorization',
            'https://id.acme.example/device',
            'https://id.acme.example/backchannel_authentication',
            'https://id.acme.example/account/approvals',
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusedUrls(): iterable
    {
        yield 'relative' => ['/authorize', 'is not an absolute URL'];
        yield 'no scheme' => ['id.acme.example/authorize', 'is not an absolute URL'];
        yield 'plain HTTP on a public host' => ['http://id.acme.example/authorize', 'must use HTTPS; plain HTTP is only accepted on a loopback host'];
        yield 'plain HTTP on a host that only looks like loopback' => ['http://localhost.attacker.example/authorize', 'must use HTTPS'];
        yield 'another scheme' => ['ftp://id.acme.example/authorize', 'must use HTTPS'];
        yield 'fragment' => ['https://id.acme.example/authorize#top', 'must not carry a fragment'];
        yield 'credentials' => ['https://user:pass@id.acme.example/authorize', 'must not carry credentials'];
        yield 'a user without a password' => ['https://user@id.acme.example/authorize', 'must not carry credentials'];
    }

    /**
     * Every endpoint is checked, and the message names the one at fault.
     */
    #[Test]
    #[DataProvider('provideEndpointsAtFault')]
    public function everyEndpointIsCheckedAndNamed(string $name, int $position, string $url): void
    {
        // Given
        $urls = array_fill(0, 12, 'https://id.acme.example/x');
        $urls[$position] = $url;

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('The ' . $name . ' endpoint "' . $url . '"');

        // When
        new ProviderEndpoints(...$urls);
    }

    /**
     * @return iterable<string, array{string, int, string}>
     */
    public static function provideEndpointsAtFault(): iterable
    {
        yield 'authorization' => ['authorization', 0, 'https://id.acme.example/a#f'];
        yield 'token' => ['token', 1, 'http://id.acme.example/t'];
        yield 'userinfo' => ['userinfo', 2, 'https://id.acme.example/u#f'];
        yield 'JWK Set' => ['JWK Set', 3, 'https://id.acme.example/j#f'];
        yield 'end session' => ['end session', 4, 'https://id.acme.example/e#f'];
        yield 'introspection' => ['introspection', 5, 'https://id.acme.example/i#f'];
        yield 'revocation' => ['revocation', 6, 'https://id.acme.example/r#f'];
        yield 'pushed authorization request' => ['pushed authorization request', 7, 'https://id.acme.example/p#f'];
        yield 'device authorization' => ['device authorization', 8, 'https://id.acme.example/d#f'];
        yield 'device verification' => ['device verification', 9, 'https://id.acme.example/v#f'];
        yield 'backchannel authentication' => ['backchannel authentication', 10, 'https://id.acme.example/b#f'];
        yield 'backchannel approval' => ['backchannel approval', 11, 'https://id.acme.example/c#f'];
    }
}
