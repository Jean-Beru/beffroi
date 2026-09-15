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
        $endpoints = new ProviderEndpoints(
            'https://id.acme.example/authorize?tenant=acme',
            'https://id.acme.example/token',
            'https://id.acme.example/userinfo',
            'https://id.acme.example/jwks',
            'https://id.acme.example/logout',
        );

        static::assertSame('https://id.acme.example/authorize?tenant=acme', $endpoints->authorization);
        static::assertSame('https://id.acme.example/token', $endpoints->token);
        static::assertSame('https://id.acme.example/userinfo', $endpoints->userinfo);
        static::assertSame('https://id.acme.example/jwks', $endpoints->jwks);
        static::assertSame('https://id.acme.example/logout', $endpoints->endSession);
    }

    /**
     * RFC 6761 §6.3: plain HTTP is tolerated on a loopback host for development, the same exception the
     * issuer makes, except for the token endpoint (RFC 6749 §3.2 requires TLS there, and oidc_login
     * refuses a token endpoint in clear even on loopback).
     */
    #[Test]
    public function itToleratesPlainHttpOnLoopbackExceptForTheTokenEndpoint(): void
    {
        $endpoints = new ProviderEndpoints('http://localhost:8000/authorize', 'HTTPS://op.localhost/token', 'http://OP.LOCALHOST/userinfo', 'http://127.0.0.1/jwks', 'http://[::1]/logout');

        static::assertSame('http://localhost:8000/authorize', $endpoints->authorization);
        static::assertSame('HTTPS://op.localhost/token', $endpoints->token);
        static::assertSame('http://OP.LOCALHOST/userinfo', $endpoints->userinfo);

        try {
            new ProviderEndpoints('https://op.localhost/authorize', 'http://localhost/token', 'https://op.localhost/userinfo', 'https://op.localhost/jwks', 'https://op.localhost/logout');
            static::fail('A token endpoint in clear is refused, on loopback too.');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('token endpoint "http://localhost/token" must use HTTPS (RFC 6749 section 3.2), on a loopback host too', $e->getMessage());
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function refusedUrls(): iterable
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
     * RFC 6749 §3.1, §3.2: absolute, no fragment, over TLS; what a relying party would use as it is must
     * be refused before it is announced.
     */
    #[Test]
    #[DataProvider('refusedUrls')]
    public function itRefusesWhatARelyingPartyMustNotUse(string $url, string $reason): void
    {
        try {
            new ProviderEndpoints($url, 'https://id.acme.example/token', 'https://id.acme.example/userinfo', 'https://id.acme.example/jwks', 'https://id.acme.example/logout');
            static::fail('The authorization endpoint is refused.');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('The authorization endpoint "' . $url . '" ' . $reason, $e->getMessage());
        }
    }

    /**
     * Every endpoint is checked, and the message names the one at fault.
     */
    #[Test]
    public function everyEndpointIsCheckedAndNamed(): void
    {
        $valid = 'https://id.acme.example/x';
        foreach ([
            'authorization' => [0, 'https://id.acme.example/a#f'],
            'token' => [1, 'http://id.acme.example/t'],
            'userinfo' => [2, 'https://id.acme.example/u#f'],
            'JWK Set' => [3, 'https://id.acme.example/j#f'],
            'end session' => [4, 'https://id.acme.example/e#f'],
        ] as $name => [$position, $url]) {
            $urls = [$valid, $valid, $valid, $valid, $valid];
            $urls[$position] = $url;
            try {
                new ProviderEndpoints(...$urls);
                static::fail('The ' . $name . ' endpoint is refused.');
            } catch (InvalidArgumentException $e) {
                static::assertStringContainsString('The ' . $name . ' endpoint "' . $url . '"', $e->getMessage());
            }
        }
    }
}
