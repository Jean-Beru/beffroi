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
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\DeviceCodeGrant;
use Beffroi\Oidc\Application\Token\RefreshTokenDue;
use Beffroi\Oidc\Application\Token\TokenIssuer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8628 §3.4, §3.5: the client polls, and is told "not yet", "slow down", "expired", "refused", or given
 * the tokens of the authorization its user approved.
 */
final class DeviceCodeGrantTest extends TestCase
{
    private const string DEVICE_CODE = 'the-device-code';

    private Client $client;

    private Client $stranger;

    private AuthenticationSession $session;

    private RequestContext $context;

    private InMemoryDeviceAuthorizationRecordRepository $records;

    private InMemoryRefreshTokenRepository $refreshTokens;

    private FakeAccessTokenIssuer $accessTokenIssuer;

    private FakeIdTokenIssuer $idTokens;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private DeviceCodeGrant $grant;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $hasher = new FakePasswordHasher();
        $this->client = Clients::appliance($tenant, $hasher->hash(Clients::SECRET));
        $this->stranger = Clients::appliance($tenant, $hasher->hash(Clients::SECRET), 'another-television');
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->session = Fixtures::session(Fixtures::user($tenant), $this->clock->now());
        $this->context = Fixtures::context($this->clock->now());
        $this->records = new InMemoryDeviceAuthorizationRecordRepository();
        $this->refreshTokens = new InMemoryRefreshTokenRepository();
        $this->accessTokenIssuer = new FakeAccessTokenIssuer();
        $this->idTokens = new FakeIdTokenIssuer();
        $this->events = new RecordingEventDispatcher();
        $this->grant = $this->grant();
    }

    #[Test]
    public function itIsNamedByTheUrnOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('urn:ietf:params:oauth:grant-type:device_code', $this->grant->grantType()->value);
    }

    /**
     * RFC 8628 §3.5: the tokens are the ones of the authorization the user approved, descending from the
     * session they approved with.
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
        static::assertTrue($authorization->grantType->equals(Grants::deviceCode()));
        static::assertSame('openid profile', (string) $authorization->scopes);
    }

    /**
     * RFC 8628 §3.5: the device code is spent by the poll that is served, as an authorization code is.
     */
    #[Test]
    public function aServedPollSpendsTheDeviceCode(): void
    {
        // Given
        $record = $this->approved();

        // When
        $this->poll();

        // Then
        static::assertTrue($record->isUsed());
        static::assertEquals($this->clock->now(), $record->usedAt);
    }

    /**
     * OIDC Core §3.1.3.7 (issue #836): the key the ID token is encrypted to is read before the device code
     * is spent, so keys the client cannot serve right now leave it to the next poll, with nothing issued.
     */
    #[Test]
    public function aDeviceCodeIsLeftUnspentWhileTheKeysOfItsClientCannotBeRead(): void
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
     * Architecture §4.5 (issue #870): the keys of the tenant the tokens are signed with are opened before the
     * device code is spent, so a KMS that does not answer leaves it to the next poll, with nothing issued.
     */
    #[Test]
    public function aDeviceCodeIsLeftUnspentWhileTheKmsDoesNotAnswer(): void
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
     * RFC 8628 §3.5: a device code is spent once, and presented again is worth nothing.
     */
    #[Test]
    public function aDeviceCodePresentedTwiceIsRefused(): void
    {
        // Given
        $this->approved();
        $this->poll();
        $this->clock->modify('+10 seconds');

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The device code is invalid.');

        // When
        $this->poll();
    }

    /**
     * RFC 8628 §3.5: the user has not answered yet, which is all the client is told.
     */
    #[Test]
    public function aRequestNobodyHasAnsweredIsPending(): void
    {
        // Given
        $this->record();

        // Then
        $this->expectException(AuthorizationPendingException::class);
        $this->expectExceptionMessageIs('authorization_pending: The end user has not answered the request yet (RFC 8628 section 3.5).');

        // When
        $this->poll();
    }

    /**
     * RFC 8628 §3.5: a poll that is not served spends nothing, so the next one can be.
     */
    #[Test]
    public function aPendingPollSpendsNothing(): void
    {
        // Given
        $record = $this->record();

        // When
        try {
            $this->poll();
        } catch (AuthorizationPendingException) {
            // the answer of this poll is not what this test is about
        }

        // Then
        static::assertFalse($record->isUsed());
    }

    /**
     * RFC 8628 §3.5: the user refused, and the client is told so rather than left polling.
     */
    #[Test]
    public function aRefusedRequestIsAnsweredAccessDenied(): void
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
     * RFC 6749 §5.2: the token endpoint answers in JSON and redirects nothing anywhere, this client having no
     * browser to send.
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
     * RFC 8628 §3.5: past its lifetime the code is dead, and the client is told to start over rather than
     * given the one answer a code nobody issued gets.
     */
    #[Test]
    public function aCodePastItsLifetimeIsAnsweredExpiredToken(): void
    {
        // Given
        $this->approved();
        $this->clock->modify('+601 seconds');

        // Then
        $this->expectException(ExpiredTokenException::class);
        $this->expectExceptionMessageIs('expired_token: The device code has expired and the client starts a new request (RFC 8628 section 3.5).');

        // When
        $this->poll();
    }

    /**
     * RFC 8628 §3.5: a client polling sooner than the interval it was given, for an answer that is not
     * there yet, is told to slow down.
     */
    #[Test]
    public function aClientPollingTooFastIsToldToSlowDown(): void
    {
        // Given
        $this->record();
        $this->pollQuietly();
        $this->clock->modify('+2 seconds');

        // Then
        $this->expectException(SlowDownException::class);
        $this->expectExceptionMessageIs('slow_down: The client is polling faster than the interval it was given, which grows by five seconds (RFC 8628 section 3.5).');

        // When
        $this->poll();
    }

    /**
     * RFC 8628 §3.5: the interval grows by five seconds, for that request and every one after it, and the
     * record remembers it so the two stay in step.
     */
    #[Test]
    public function beingToldToSlowDownGrowsTheIntervalOnTheRecord(): void
    {
        // Given
        $record = $this->record();
        $this->pollQuietly();
        $this->clock->modify('+2 seconds');

        // When
        $this->pollQuietly();

        // Then
        static::assertSame(10, $record->interval);
    }

    /**
     * RFC 8628 §3.5: a client that waited the interval it was given is served.
     */
    #[Test]
    public function aClientThatWaitedTheIntervalIsServed(): void
    {
        // Given
        $record = $this->record();
        $this->pollQuietly();
        $record->approve(
            $this->session,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $this->clock->now(),
        );
        $this->clock->modify('+5 seconds');

        // When
        $issued = $this->poll();

        // Then
        static::assertTrue($record->isUsed());
        static::assertNotSame('', $issued->accessToken->value);
    }

    /**
     * RFC 8628 §3.5: "slow_down" is a variant of "authorization_pending", so it has nothing to say about
     * a request the user has answered; the interval bounds the wait and only the wait.
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
        $this->poll();

        // Then
        static::assertTrue($record->isUsed());
    }

    /**
     * RFC 8628 §3.5: the refusal is on the same clock as the acceptance, an answered request being over
     * whichever way it was answered.
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
     * RFC 8628 §3.5: a code the store does not hold, and a code of another client, are the one refusal a
     * guessing client gets.
     */
    #[Test]
    #[DataProvider('provideCodesThatGrantNothing')]
    public function aCodeThatGrantsNothingIsRefused(string $case): void
    {
        // Given
        $this->approved();
        $presentedBy = $case === 'another client' ? $this->stranger : $this->client;

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The device code is invalid.');

        // When
        $this->grant->grant(
            new AuthenticatedClient($presentedBy),
            RequestParameters::of([
                'device_code' => $case === 'a code nobody issued' ? 'another-device-code' : self::DEVICE_CODE,
            ]),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCodesThatGrantNothing(): iterable
    {
        yield 'a code nobody issued' => ['a code nobody issued'];
        yield 'a code of another client' => ['another client'];
    }

    /**
     * RFC 8628 §3.4: the request names the device code, and one that names none names nothing to look up.
     */
    #[Test]
    public function itRequiresTheDeviceCode(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The device_code parameter is missing.');

        // When
        $this->grant->grant(new AuthenticatedClient($this->client), RequestParameters::of([]), $this->context);
    }

    /**
     * Architecture §4.6: a session that has ended grants nothing, whatever it once approved.
     */
    #[Test]
    public function aSessionThatEndedGrantsNothing(): void
    {
        // Given
        $this->approved();
        $this->session->end(SessionEnd::User, $this->clock->now());

        // Then
        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionMessageIs('invalid_grant: The device code is invalid.');

        // When
        $this->poll();
    }

    /**
     * RFC 6749 §4.1.4, OIDC Core §11: a confidential client registered for the renewal gets a refresh token,
     * in a family descending from the device code it spent.
     */
    #[Test]
    public function anApplianceGetsARefreshTokenInAFamilyDescendingFromItsDeviceCode(): void
    {
        // Given
        $this->approved();

        // When
        $issued = $this->poll();

        // Then
        $refreshToken = $issued->refreshToken ?? static::fail('A refresh token was issued.');
        static::assertSame(DrawnSecret::digestOf(self::DEVICE_CODE), $refreshToken->token->family->grantingRecordHash);
        static::assertSame($issued->authorization->grantId, $refreshToken->token->family->grantId);
    }

    /**
     * RFC 8705 §3, RFC 9449 §5: the tokens are bound to what this request proved, the browser that approved
     * holding nothing the appliance can prove.
     */
    #[Test]
    public function theTokensAreBoundToWhatThePollProved(): void
    {
        // Given
        $this->approved();
        $confirmation = new KeyConfirmation('0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I');

        // When
        $issued = $this->grant->grant(
            new AuthenticatedClient($this->client, $confirmation),
            RequestParameters::of([
                'device_code' => self::DEVICE_CODE,
            ]),
            $this->context,
        );

        // Then
        static::assertSame($confirmation, $issued->authorization->confirmation);
    }

    /**
     * RFC 8707 §2: the access token is addressed to the resource the device authorization request named, the
     * poll being no second chance to ask.
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

    private function poll(): IssuedTokens
    {
        return $this->grant->grant(
            new AuthenticatedClient($this->client),
            RequestParameters::of([
                'device_code' => self::DEVICE_CODE,
            ]),
            $this->context,
        );
    }

    /**
     * A poll whose answer is not what the test is about.
     */
    private function pollQuietly(): void
    {
        try {
            $this->poll();
        } catch (OAuth2Exception) {
            // the answer of this poll is not what the test is about
        }
    }

    private function record(?ResourceIndicators $resources = null): DeviceAuthorizationRecord
    {
        $record = new DeviceAuthorizationRecord(
            DrawnSecret::digestOf(self::DEVICE_CODE),
            UserCode::hashOf('BCDFGHJK'),
            Uuid::v7(),
            $this->client,
            new Scopes([new Scope('openid'), new Scope('profile')]),
            $resources,
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+600 seconds'),
        );
        $this->records->save($record);

        return $record;
    }

    private function approved(?ResourceIndicators $resources = null): DeviceAuthorizationRecord
    {
        $record = $this->record($resources);
        $record->approve(
            $this->session,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $this->clock->now(),
        );

        return $record;
    }

    private function grant(?DateInterval $familyLifetime = null): DeviceCodeGrant
    {
        return new DeviceCodeGrant(
            $this->records,
            new TokenIssuer($this->accessTokenIssuer, $this->idTokens, $this->refreshTokens, Secrets::drawer(), $this->events),
            new RefreshTokenDue(Grants::served()),
            new SymfonyUuidGenerator(),
            $this->clock,
            $familyLifetime ?? new DateInterval('P90D'),
        );
    }
}
