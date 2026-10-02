<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\EndSession;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use function array_keys;
use function explode;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\EndSession\LogoutTokenIssuer;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Tests\Fixture\ClientEncryption;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Beffroi\Oidc\Tests\Fixture\Shapes;

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
        $this->issuer = new LogoutTokenIssuer($this->jwts->signer, Subjects::publicKind(), Algorithms::all(), new SymfonyUuidGenerator());
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
        static::assertSame(
            [
                'typ' => 'logout+jwt',
                'alg' => 'RS256',
                'kid' => $this->jwts->key->kid,
            ],
            $header,
        );
    }

    /**
     * Back-Channel Logout 1.0 §2.6: the logout token is signed in the algorithm the client registered for
     * its ID tokens, since that is the one it knows how to verify.
     */
    #[Test]
    public function theTokenIsSignedWithTheAlgorithmTheClientRegistered(): void
    {
        // Given
        $es256Key = $this->jwts->activate(Algorithms::es256());
        $client = new Client(
            $this->session->tenant,
            new ClientRegistration(
                'spa',
                new ClientPresentation('Single page application'),
                Methods::none(),
                false,
                [new RedirectUri('https://spa.example/callback')],
                Shapes::jwt(),
                backChannelLogoutUri: new ClientUri('https://spa.example/backchannel-logout'),
                idToken: ResponseFormat::signed(Algorithms::es256()),
            ),
        );

        // When
        $token = $this->issuer->issue($client, $this->session, Fixtures::now());

        // Then
        ['header' => $header] = $this->jwts->verify($token, 'spa', Fixtures::now(), self::MANDATORY);
        static::assertSame(
            [
                'typ' => 'logout+jwt',
                'alg' => 'ES256',
                'kid' => $es256Key->kid,
            ],
            $header,
        );
    }

    /**
     * The logout token reads the algorithm of the ID token registration and nothing else of it: a client
     * that registered an encryption for its ID tokens receives a logout token signed and in clear, because
     * Back-Channel Logout 1.0 registers no shape of its own for it and the provider announces none.
     */
    #[Test]
    public function theTokenIsNotEncryptedForAClientWhoseIdTokensAre(): void
    {
        // Given
        $client = Clients::encryptedFor($this->session->tenant, idToken: ResponseFormat::signed(null, ClientEncryption::registration()));

        // When
        $token = $this->issuer->issue($client, $this->session, Fixtures::now());

        // Then
        static::assertCount(3, explode('.', $token));
        static::assertSame('logout+jwt', $this->jwts->verify($token, 'encrypted-client', Fixtures::now(), self::MANDATORY)['header']['typ']);
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
        static::assertSame(
            [
                'http://schemas.openid.net/event/backchannel-logout' => [],
            ],
            $claims['events'],
        );
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
        static::assertSame(Subjects::publicKind()->resolve($this->session->user, $this->client)->value, $claims['sub']);
    }
}
