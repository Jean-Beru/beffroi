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
     * Back-Channel Logout 1.0 §2.4
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
        static::assertSame(1789639400, $claims['exp']);
        static::assertSame(self::JTI, $claims['jti']);
        static::assertSame(self::SESSION, $claims['sid']);
    }

    /**
     * Back-Channel Logout 1.0 §2.4
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
     * Back-Channel Logout 1.0 §2.4
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
        yield 'at_hash' => ['at_hash'];
        yield 'auth_time' => ['auth_time'];
    }

    /**
     * Back-Channel Logout 1.0 §2.4
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
     * Back-Channel Logout 1.0 §2.4
     */
    #[Test]
    public function itCarriesNothingElse(): void
    {
        // When
        $claims = Jwts::decode(JwtPayload::encode(self::token()->claims()));

        // Then
        static::assertSame(['iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'events', 'sid'], array_keys($claims));
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
            new DateTimeImmutable('@1789639400'),
        );
    }
}
