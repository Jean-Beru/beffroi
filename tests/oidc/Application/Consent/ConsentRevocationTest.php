<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Consent;

use function array_map;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Consent\ConsentRevocation;
use Heidi\Oidc\Application\Grant\RecordedGrants;
use Heidi\Oidc\Application\Token\RefreshTokenRevocation;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Event\ConsentRevoked;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.3: what a user taking back what they agreed to comes to. The consent goes, and what was
 * issued under it goes with it: the grants the client left behind, the refresh tokens, the opaque access
 * tokens. What belongs to another client, to another user or to no user at all is left alone.
 */
final class ConsentRevocationTest extends TestCase
{
    private Tenant $tenant;

    private User $user;

    private Client $client;

    private Client $other;

    private AuthenticationSession $session;

    private RequestContext $context;

    private InMemoryConsentRepository $consents;

    private InMemoryAuthorizationCodeRepository $codes;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private InMemoryAccessTokenRepository $accessTokens;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private ConsentRevocation $revocation;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->other = Clients::public($this->tenant, 'another-app');
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->user = Fixtures::user($this->tenant);
        $this->session = Fixtures::session($this->user, $this->clock->now());
        $this->context = Fixtures::context($this->clock->now());
        $this->consents = new InMemoryConsentRepository();
        $this->codes = new InMemoryAuthorizationCodeRepository();
        $deviceRecords = new InMemoryDeviceAuthorizationRecordRepository();
        $backchannelRecords = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->accessTokens = new InMemoryAccessTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->revocation = new ConsentRevocation(
            $this->consents,
            new RecordedGrants([$this->codes, $deviceRecords, $backchannelRecords]),
            new RefreshTokenRevocation($this->refreshTokens),
            $this->refreshTokens,
            $this->accessTokens,
            $this->events,
            $this->clock,
        );
    }

    #[Test]
    public function theConsentIsRevokedAtThisInstant(): void
    {
        // Given
        $consent = $this->consent();

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertFalse($consent->isActive());
        static::assertEquals($this->clock->now(), $consent->revokedAt);
        static::assertNull($this->consents->findActive($this->user, $this->client));
    }

    #[Test]
    public function theGrantsThatClientHoldsForThatUserAreRevoked(): void
    {
        // Given
        $consent = $this->consent();
        $code = $this->code('the-code', $this->client);

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertTrue($code->isRevoked());
        static::assertEquals($this->clock->now(), $code->revokedAt);
    }

    #[Test]
    public function aGrantOfAnotherClientIsLeftAlone(): void
    {
        // Given
        $consent = $this->consent();
        $elsewhere = $this->code('the-other-code', $this->other);

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertFalse($elsewhere->isRevoked());
    }

    #[Test]
    public function aGrantOfAnotherUserIsLeftAlone(): void
    {
        // Given
        $consent = $this->consent();
        $session = Fixtures::session(Fixtures::user($this->tenant, 'bob', 'bob-subject'), $this->clock->now());
        $elsewhere = Tokens::code('the-code-of-bob', $this->client, $session, $this->clock->now());
        $this->codes->save($elsewhere);

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertFalse($elsewhere->isRevoked());
    }

    #[Test]
    public function theRefreshTokensThatClientHoldsForThatUserAreRevoked(): void
    {
        // Given
        $consent = $this->consent();
        $token = $this->refreshToken('the-refresh-token', $this->client);
        $elsewhere = $this->refreshToken('the-other-refresh-token', $this->other);

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertTrue($token->isRevoked());
        static::assertFalse($elsewhere->isRevoked());
    }

    #[Test]
    public function theOpaqueAccessTokensThatClientHoldsForThatUserBecomeUnknown(): void
    {
        // Given
        $consent = $this->consent();
        $this->accessTokens->save(Tokens::storedAccessToken('the-access-token', $this->client, $this->session, $this->clock->now()));
        $this->accessTokens->save(Tokens::storedAccessToken('the-other-access-token', $this->other, $this->session, $this->clock->now()));

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertNull($this->accessTokens->find('the-access-token'));
        static::assertNotNull($this->accessTokens->find('the-other-access-token'));
    }

    /**
     * RFC 6749 §4.4: a token a client holds for itself descends from no user and from no consent.
     */
    #[Test]
    public function theTokenTheClientHoldsForItselfIsLeftAlone(): void
    {
        // Given
        $consent = $this->consent();
        $this->accessTokens->save(Tokens::storedClientAccessToken('the-token-of-the-client', $this->client, $this->clock->now()));

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertNotNull($this->accessTokens->find('the-token-of-the-client'));
    }

    #[Test]
    public function theEventNamesTheConsentAndEverythingThatWentWithIt(): void
    {
        // Given
        $consent = $this->consent();
        $code = $this->code('the-code', $this->client);
        $refreshToken = $this->refreshToken('the-refresh-token', $this->client);
        $this->accessTokens->save(Tokens::storedAccessToken('the-access-token', $this->client, $this->session, $this->clock->now()));

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        $event = $this->events->of(ConsentRevoked::class)[0] ?? static::fail('The revocation said nothing.');
        static::assertEquals($this->clock->now(), $event->occurredAt);
        static::assertTrue($event->tenant->equals($this->tenant));
        static::assertTrue($event->consentId->equals($consent->id));
        static::assertSame($this->client->registration->clientId, $event->clientId);
        static::assertTrue($event->userId->equals($this->user->id));
        static::assertSame(
            [$code->grantId->toRfc4122()],
            array_map(static fn (Uuid $grantId): string => $grantId->toRfc4122(), $event->revokedGrants),
        );
        static::assertSame([$refreshToken->tokenHash], $event->revokedRefreshTokenHashes);
        static::assertSame([DrawnSecret::digestOf('the-access-token')], $event->revokedAccessTokenHashes);
        static::assertSame($this->context, $event->context);
    }

    /**
     * A grant revoked before, by the replay of its code, keeps the date it was revoked on and is not
     * counted a second time.
     */
    #[Test]
    public function aGrantAlreadyRevokedKeepsItsDate(): void
    {
        // Given
        $consent = $this->consent();
        $code = $this->code('the-code', $this->client);
        $code->revoke($this->clock->now()->modify('-1 hour'));

        // When
        $this->revocation->revoke($consent, $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('-1 hour'), $code->revokedAt);
        static::assertSame([], $this->events->of(ConsentRevoked::class)[0]->revokedGrants ?? static::fail('The revocation said nothing.'));
    }

    private function consent(): Consent
    {
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([new Scope('openid')]), $this->clock->now());
        $this->consents->save($consent);

        return $consent;
    }

    private function code(string $value, Client $client): AuthorizationCode
    {
        $code = Tokens::code($value, $client, $this->session, $this->clock->now());
        $this->codes->save($code);

        return $code;
    }

    private function refreshToken(string $value, Client $client): RefreshToken
    {
        $token = Tokens::refreshToken($value, $client, $this->session, $this->clock->now());
        $this->refreshTokens->save($token);

        return $token;
    }
}
