<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\EndSession;

use function array_keys;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Application\EndSession\LogoutTokenIssuer;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Jwts;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Back-Channel Logout 1.0 §2.4 and §2.6: what the provider signs for a client of a session that ended,
 * verified the way that client verifies it, against the published JWK Set.
 */
final class LogoutTokenIssuerTest extends TestCase
{
    private const array MANDATORY = ['iss', 'aud', 'iat'];

    private AuthenticationSession $session;

    private Client $client;

    private Jwts $jwts;

    private LogoutTokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::withBackChannelLogout($this->session->tenant);
        $this->jwts = new Jwts($this->session->tenant);
        $this->issuer = new LogoutTokenIssuer($this->jwts->signer, new PublicSubjectIdentifierResolver());
    }

    /**
     * Back-Channel Logout 1.0 §2.4: "typ" is "logout+jwt", which is how a client refuses an ID token
     * offered as a logout token; the key is the active one of the tenant.
     */
    #[Test]
    public function theHeaderNamesTheActiveKeyAndTheLogoutType(): void
    {
        // Given
        $token = $this->issuer->issue($this->client, $this->session, Fixtures::now());

        // When
        ['header' => $header] = $this->jwts->verify($token, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame([
            'typ' => 'logout+jwt',
            'alg' => 'RS256',
            'kid' => $this->jwts->key->kid,
        ], $header);
    }

    /**
     * Back-Channel Logout 1.0 §2.4: the claims of the section, and them alone.
     */
    #[Test]
    public function thePayloadCarriesTheClaimsOfTheSpecification(): void
    {
        // Given
        $token = $this->issuer->issue($this->client, $this->session, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame(['iss', 'sub', 'aud', 'iat', 'jti', 'events', 'sid'], array_keys($claims));
        static::assertSame('https://id.acme.example', $claims['iss']);
        static::assertSame('alice-subject', $claims['sub']);
        static::assertSame('spa', $claims['aud']);
        static::assertSame(Fixtures::now()->getTimestamp(), $claims['iat']);
        static::assertSame($this->session->id->toRfc4122(), $claims['sid']);
    }

    /**
     * Back-Channel Logout 1.0 §2.4: the one member of "events", an empty JSON object.
     */
    #[Test]
    public function thePayloadAnnouncesTheBackChannelLogoutEvent(): void
    {
        // Given
        $token = $this->issuer->issue($this->client, $this->session, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame([
            'http://schemas.openid.net/event/backchannel-logout' => [],
        ], $claims['events']);
    }

    /**
     * RFC 7519 §4.1.7: two logout tokens never carry the same "jti", or a client would take the second
     * for the replay of the first (Back-Channel Logout 1.0 §2.6).
     */
    #[Test]
    public function eachTokenCarriesAnIdentifierOfItsOwn(): void
    {
        // Given
        $first = $this->issuer->issue($this->client, $this->session, Fixtures::now());

        // When
        $second = $this->issuer->issue($this->client, $this->session, Fixtures::now());

        // Then
        static::assertNotSame(
            $this->jwts->verify($first, 'spa', Fixtures::now(), self::MANDATORY)['claims']['jti'],
            $this->jwts->verify($second, 'spa', Fixtures::now(), self::MANDATORY)['claims']['jti'],
        );
    }

    /**
     * OIDC Core §8: the client reads the subject it already knows, never the internal identifier.
     */
    #[Test]
    public function theSubjectIsTheOneTheClientAlreadySees(): void
    {
        // Given
        $token = $this->issuer->issue($this->client, $this->session, Fixtures::now());

        // When
        ['claims' => $claims] = $this->jwts->verify($token, 'spa', Fixtures::now(), self::MANDATORY);

        // Then
        static::assertSame(new PublicSubjectIdentifierResolver()->resolve($this->session->user, $this->client)->value, $claims['sub']);
    }
}
