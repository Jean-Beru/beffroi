<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\EndSession;

use function array_keys;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\EndSession\LogoutToken;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class LogoutTokenTest extends TestCase
{
    private const string SESSION = '0199a0f2-7c3e-7000-8000-0000000000a1';

    private const string JTI = '0199a0f2-7c3e-7000-8000-0000000000b2';

    /**
     * Back-Channel Logout 1.0 §2.4: the claims a logout token carries, and the "sub" the client sees.
     */
    #[Test]
    public function itCarriesTheClaimsOfASessionThatEnded(): void
    {
        // When
        $claims = self::token()->claims();

        // Then
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame('alice-for-the-client', $claims['sub']);
        static::assertSame('oidc-demo', $claims['aud']);
        static::assertSame(1789639200, $claims['iat']);
        static::assertSame(self::JTI, $claims['jti']);
        static::assertSame(self::SESSION, $claims['sid']);
    }

    /**
     * Back-Channel Logout 1.0 §2.4: one member, named by the event URI, whose value is an empty JSON
     * object and not an empty array, which is what a client looks for to tell a logout from any other SET.
     */
    #[Test]
    public function itAnnouncesTheOneBackChannelLogoutEvent(): void
    {
        // When
        $payload = JwtPayload::encode(self::token()->claims());

        // Then
        static::assertStringContainsString('"events":{"http://schemas.openid.net/event/backchannel-logout":{}}', $payload);
    }

    /**
     * Back-Channel Logout 1.0 §2.4: a "nonce" is forbidden, so that a logout token can never be taken
     * for an ID token; RFC 8417 §2: a security event token states what happened and does not expire.
     */
    #[Test]
    #[DataProvider('provideForbiddenClaims')]
    public function itCarriesNothingThatWouldMakeItAnIdToken(string $claim): void
    {
        // When
        $claims = self::token()->claims();

        // Then
        static::assertArrayNotHasKey($claim, $claims);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideForbiddenClaims(): iterable
    {
        yield 'nonce (Back-Channel Logout 1.0 §2.4)' => ['nonce'];
        yield 'exp (RFC 8417 §2)' => ['exp'];
        yield 'at_hash' => ['at_hash'];
        yield 'auth_time' => ['auth_time'];
    }

    /**
     * Back-Channel Logout 1.0 §2.4 requires a "sub" or a "sid"; the provider sends both, so that a client
     * finds the session whether it kept one per subject or one per "sid".
     */
    #[Test]
    public function itNamesBothTheSubjectAndTheSession(): void
    {
        // When
        $claims = array_keys(self::token()->claims());

        // Then
        static::assertContains('sub', $claims);
        static::assertContains('sid', $claims);
    }

    /**
     * The payload is a JSON object whose members are those of §2.4 and no others.
     */
    #[Test]
    public function itCarriesNothingElse(): void
    {
        // When
        $claims = Jwts::decode(JwtPayload::encode(self::token()->claims()));

        // Then
        static::assertSame(['iss', 'sub', 'aud', 'iat', 'jti', 'events', 'sid'], array_keys($claims));
    }

    private static function token(): LogoutToken
    {
        return new LogoutToken(
            new Issuer('https://id.acme.example'),
            'oidc-demo',
            new Subject('alice-for-the-client'),
            Uuid::fromString(self::SESSION),
            Uuid::fromString(self::JTI),
            new DateTimeImmutable('@1789639200'),
        );
    }
}
