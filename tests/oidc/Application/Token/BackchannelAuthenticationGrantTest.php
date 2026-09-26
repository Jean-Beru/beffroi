<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use DateInterval;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Heidi\Oidc\Application\Token\RefreshTokenDue;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Domain\Token\UserAuthorizationInterface;
use Heidi\Oidc\Exception\AccessDeniedException;
use Heidi\Oidc\Exception\AuthorizationPendingException;
use Heidi\Oidc\Exception\ExpiredTokenException;
use Heidi\Oidc\Exception\InvalidGrantException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\SlowDownException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Heidi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §10.1, §11: the client comes back, and is told "not yet", "slow down", "expired", "refused",
 * or given the tokens of the authorization its user approved.
 */
final class BackchannelAuthenticationGrantTest extends TestCase
{
    private const string AUTH_REQUEST_ID = 'the-auth-req-id';

    private Client $client;

    private Client $stranger;

    private AuthenticationSession $session;

    private RequestContext $context;

    private InMemoryBackchannelAuthenticationRecordRepository $records;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private BackchannelAuthenticationGrant $grant;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $hasher = new FakePasswordHasher();
        $this->client = Clients::backchannel($tenant, $hasher->hash(Clients::SECRET));
        $this->stranger = Clients::backchannel($tenant, $hasher->hash(Clients::SECRET), 'another-terminal');
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->session = Fixtures::session(Fixtures::user($tenant), $this->clock->now());
        $this->context = Fixtures::context($this->clock->now());
        $this->records = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->events = new RecordingEventDispatcher();
        $this->grant = $this->grant();
    }

    /**
     * CIBA Core §7.3: the grant is named by the URI of the specification.
     */
    #[Test]
    public function itIsNamedByTheUrnOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('urn:openid:params:grant-type:ciba', $this->grant->grantType()->value);
    }

    /**
     * §10.1: the tokens are the ones of the authorization the user approved, descending from the session
     * they approved with.
     */
    #[Test]
    public function anApprovedRequestYieldsTheAuthorizationTheUserApproved(): void
    {
        // Given
        $this->approved();

        // When
        $issued = $this->poll();

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(UserAuthorizationInterface::class, $authorization);
        static::assertSame($this->client, $authorization->client);
        static::assertSame($this->session, $authorization->session);
        static::assertTrue($authorization->grantType->equals(Grants::ciba()));
        static::assertSame('openid profile', (string) $authorization->scopes);
    }

    /**
     * §10.1: "openid" being required of every request of this flow, the answer carries an ID token.
     */
    #[Test]
    public function theAnswerCarriesAnIdToken(): void
    {
        // Given
        $this->approved();

        // When
        $issued = $this->poll();

        // Then
        static::assertNotNull($issued->idToken);
    }

    /**
     * §10.1: the identifier is spent by the request that is served, as an authorization code is.
     */
    #[Test]
    public function aServedRequestSpendsTheIdentifier(): void
    {
        // Given
        $record = $this->approved();

        // When
        $this->poll();

        // Then
        static::assertTrue($record->isUsed());
    }

    /**
     * §10.1: an identifier presented again is worth nothing.
     */
    #[Test]
    public function anIdentifierPresentedTwiceIsWorthNothing(): void
    {
        // Given
        $this->approved();
        $this->poll();
        $this->clock->modify('+10 seconds');

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The auth_req_id is invalid.');

        // When
        $this->poll();
    }

    /**
     * §11: while the user has not answered, the client is told "not yet" and nothing else.
     */
    #[Test]
    public function aRequestNobodyAnsweredIsPending(): void
    {
        // Given
        $this->record();

        // Then
        $this->expectException(AuthorizationPendingException::class);
        $this->expectExceptionMessageIs('authorization_pending: The end user has not answered the request yet (CIBA Core section 11).');

        // When
        $this->poll();
    }

    /**
     * §11: the user said no.
     */
    #[Test]
    public function aRefusedRequestIsAccessDenied(): void
    {
        // Given
        $record = $this->record();
        $record->deny($this->clock->now());

        // Then
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessageIs('access_denied: The end user denied the request.');

        // When
        $this->poll();
    }

    /**
     * §11: a client asking faster than the interval it was given is told to slow down.
     */
    #[Test]
    public function aRequestFasterThanTheIntervalIsToldToSlowDown(): void
    {
        // Given
        $this->record();
        $this->pollQuietly();

        // Then
        $this->expectException(SlowDownException::class);
        $this->expectExceptionMessageIs('slow_down: The client is polling faster than the interval it was given, which grows by five seconds (CIBA Core section 11).');

        // When
        $this->poll();
    }

    /**
     * §11: an identifier past its lifetime grants nothing, and the client starts a new request.
     */
    #[Test]
    public function anExpiredRequestIsToldSo(): void
    {
        // Given
        $this->approved();
        $this->clock->modify('+301 seconds');

        // Then
        $this->expectException(ExpiredTokenException::class);
        $this->expectExceptionMessageIs('expired_token: The auth_req_id has expired and the client starts a new request (CIBA Core section 11).');

        // When
        $this->poll();
    }

    /**
     * §10.1: an identifier of another client is worth nothing, whoever holds it.
     */
    #[Test]
    public function anIdentifierOfAnotherClientIsWorthNothing(): void
    {
        // Given
        $this->approved();

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The auth_req_id is invalid.');

        // When
        $this->grant->grant(
            new AuthenticatedClient($this->stranger),
            RequestParameters::of([
                'auth_req_id' => self::AUTH_REQUEST_ID,
            ]),
            $this->context,
        );
    }

    /**
     * An identifier nobody ever issued is told from one that was spent by nothing at all.
     */
    #[Test]
    public function anIdentifierNobodyIssuedIsWorthNothing(): void
    {
        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The auth_req_id is invalid.');

        // When
        $this->poll();
    }

    /**
     * RFC 6749 §3.1: the request names what it comes back with.
     */
    #[Test]
    public function aRequestWithoutAnIdentifierIsRefused(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The auth_req_id parameter is missing.');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), RequestParameters::of([]), $this->context);
    }

    /**
     * Architecture §4.6: a session that ended grants nothing afterwards, whatever the record says.
     */
    #[Test]
    public function aSessionThatEndedGrantsNothing(): void
    {
        // Given
        $this->approved();
        $this->session->end(SessionEnd::User, $this->clock->now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The auth_req_id is invalid.');

        // When
        $this->poll();
    }

    /**
     * RFC 8705 §3, RFC 9449 §5: the tokens are bound to what this request proved, the browser that
     * approved holding nothing the client can prove.
     */
    #[Test]
    public function theTokensAreBoundToWhatTheRequestProved(): void
    {
        // Given
        $this->approved();
        $confirmation = new KeyConfirmation('0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I');

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->client, $confirmation),
            RequestParameters::of([
                'auth_req_id' => self::AUTH_REQUEST_ID,
            ]),
            $this->context,
        );

        // Then
        static::assertSame($confirmation, $issued->authorization->confirmation);
    }

    /**
     * RFC 8707 §2: the access token is addressed to the resource the backchannel request named, the
     * token request being no second chance to ask.
     */
    #[Test]
    public function theTokenIsAddressedToTheResourceTheRequestNamed(): void
    {
        // Given
        $this->approved(new ResourceIndicators([new ResourceIndicator(Clients::CALENDAR)]));

        // When
        $issued = $this->poll();

        // Then
        static::assertSame([Clients::CALENDAR], $issued->authorization->audience()->values);
    }

    /**
     * RFC 6749 §4.1.4: the refresh token descends from the record the authorization was granted through,
     * as it does from an authorization code.
     */
    #[Test]
    public function theRefreshTokenFamilyDescendsFromTheRequest(): void
    {
        // Given
        $record = $this->approved();

        // When
        $issued = $this->poll();

        // Then
        static::assertSame($record->authRequestIdHash, $issued->refreshToken?->token->family->grantingRecordHash);
    }

    private function poll(): IssuedTokens
    {
        return $this->grant->grant(
            new AuthenticatedClient($this->client),
            RequestParameters::of([
                'auth_req_id' => self::AUTH_REQUEST_ID,
            ]),
            $this->context,
        );
    }

    /**
     * A request whose answer is not what the test is about.
     */
    private function pollQuietly(): void
    {
        try {
            $this->poll();
        } catch (OAuth2Exception) {
            // the answer of this request is not what the test is about
        }
    }

    private function record(?ResourceIndicators $resources = null): BackchannelAuthenticationRecord
    {
        $record = new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf(self::AUTH_REQUEST_ID),
            Uuid::v7(),
            $this->client,
            $this->session->user,
            new Scopes([new Scope('openid'), new Scope('profile')]),
            $resources,
            null,
            null,
            null,
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+300 seconds'),
        );
        $this->records->save($record);

        return $record;
    }

    private function approved(?ResourceIndicators $resources = null): BackchannelAuthenticationRecord
    {
        $record = $this->record($resources);
        $record->approve(
            $this->session,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $this->clock->now(),
        );

        return $record;
    }

    private function grant(?DateInterval $familyLifetime = null): BackchannelAuthenticationGrant
    {
        return new BackchannelAuthenticationGrant(
            $this->records,
            new TokenIssuer(new FakeAccessTokenIssuer(), new FakeIdTokenIssuer(), $this->refreshTokens, Secrets::drawer(), $this->events),
            new RefreshTokenDue(Grants::servedWithCiba()),
            new SymfonyUuidGenerator(),
            $this->clock,
            $familyLifetime ?? new DateInterval('P90D'),
        );
    }
}
