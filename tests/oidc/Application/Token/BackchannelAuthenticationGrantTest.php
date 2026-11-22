<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Exception\KmsUnavailableException;
use DateInterval;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\UnopenedRows;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\BackchannelAuthenticationGrant;
use Beffroi\Oidc\Application\Token\RefreshTokenDue;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\AccessDeniedException;
use Beffroi\Oidc\Exception\AuthorizationPendingException;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\ExpiredTokenException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\SlowDownException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\FakeIdTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §10.1, §11
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

    private FakeAccessTokenIssuer $accessTokenIssuer;

    private FakeIdTokenIssuer $idTokens;

    private RecordingEventDispatcher $events;

    private UnopenedRows $rows;

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
        $this->accessTokenIssuer = new FakeAccessTokenIssuer();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->events = new RecordingEventDispatcher();
        $this->rows = new UnopenedRows();
        $this->grant = $this->grant();
    }

    /**
     * CIBA Core §7.3
     */
    #[Test]
    public function itIsNamedByTheUrnOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('urn:openid:params:grant-type:ciba', $this->grant->grantType()->value);
    }

    /**
     * CIBA Core §10.1
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
     * CIBA Core §10.1
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
     * CIBA Core §10.1
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
     * OIDC Core §3.1.3.7
     */
    #[Test]
    public function anIdentifierIsLeftUnspentWhileTheKeysOfItsClientCannotBeRead(): void
    {
        // Given
        $record = $this->approved();
        $this->idTokens->unreadableKeys = new ClientKeysUnavailableException('The keys of the client cannot be read.');

        // When
        try {
            $this->poll();
        } catch (ClientKeysUnavailableException) {
        }

        // Then
        static::assertFalse($record->isUsed());
        static::assertSame([], $this->refreshTokens->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function anIdentifierIsLeftUnspentWhileTheKmsDoesNotAnswer(): void
    {
        // Given
        $record = $this->approved();
        $this->accessTokenIssuer->kmsOutage = new KmsUnavailableException('The KMS did not answer.');

        // When
        try {
            $this->poll();
        } catch (KmsUnavailableException) {
        }

        // Then
        static::assertFalse($record->isUsed());
        static::assertSame([], $this->refreshTokens->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function anIdentifierIsLeftUnspentWhileItsSessionCannotBeOpened(): void
    {
        // Given
        $record = $this->approved();
        $this->rows->unopen($this->session);
        $this->rows->outage = new KmsUnavailableException('The KMS did not answer.');

        // When
        try {
            $this->poll();
        } catch (KmsUnavailableException) {
        }

        // Then
        static::assertFalse($record->isUsed());
        static::assertSame([], $this->refreshTokens->all());
        static::assertSame([], $this->events->events);
    }

    /**
     * CIBA Core §10.1
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
     * CIBA Core §11
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
     * CIBA Core §11
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
     * RFC 6749 §5.2
     */
    #[Test]
    public function theRefusalOfThisGrantIsNotRedirected(): void
    {
        // Given
        $record = $this->record();
        $record->deny($this->clock->now());

        // When
        try {
            $this->poll();
            static::fail('A refused request is refused.');
        } catch (AccessDeniedException $exception) {
            // Then
            static::assertFalse($exception->redirectable);
        }
    }

    /**
     * CIBA Core §11
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
     * CIBA Core §10.2, §11
     */
    #[Test]
    public function aRequestApprovedSinceTheLastPollIsServedHoweverSoonAfterIt(): void
    {
        // Given
        $record = $this->record();
        $this->pollQuietly();
        $record->approve(
            $this->session,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $this->clock->now(),
        );

        // When
        $issued = $this->poll();

        // Then
        $authorization = $issued->authorization;
        static::assertInstanceOf(UserAuthorizationInterface::class, $authorization);
        static::assertSame($this->session, $authorization->session);
    }

    /**
     * CIBA Core §10.2, §11
     */
    #[Test]
    public function aRequestRefusedSinceTheLastPollIsAccessDeniedHoweverSoonAfterIt(): void
    {
        // Given
        $record = $this->record();
        $this->pollQuietly();
        $record->deny($this->clock->now());

        // Then
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessageIs('access_denied: The end user denied the request.');

        // When
        $this->poll();
    }

    /**
     * CIBA Core §11
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
     * CIBA Core §10.1
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
     * RFC 6749 §3.1
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
     * Architecture §4.6
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
     * RFC 8705 §3, RFC 9449 §5
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
     * RFC 8707 §2
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
     * RFC 6749 §4.1.4
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

    private function pollQuietly(): void
    {
        try {
            $this->poll();
        } catch (OAuth2Exception) {
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
            [],
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
            new TokenIssuer($this->accessTokenIssuer, $this->idTokens, $this->refreshTokens, Secrets::drawer(), $this->events),
            new RefreshTokenDue(Grants::servedWithCiba()),
            new SymfonyUuidGenerator(),
            $this->clock,
            $familyLifetime ?? new DateInterval('P90D'),
        );
    }
}
