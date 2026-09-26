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
use Heidi\Oidc\Application\Token\DeviceCodeGrant;
use Heidi\Oidc\Application\Token\RefreshTokenDue;
use Heidi\Oidc\Application\Token\TokenIssuer;
use Heidi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Heidi\Oidc\Domain\Device\UserCode;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\IssuedTokens;
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
     * RFC 8628 §3.5: a client polling sooner than the interval it was given is told to slow down, whatever
     * the user has answered.
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
            new TokenIssuer(new FakeAccessTokenIssuer(), new FakeIdTokenIssuer(), $this->refreshTokens, Secrets::drawer(), $this->events),
            new RefreshTokenDue(Grants::served()),
            new SymfonyUuidGenerator(),
            $this->clock,
            $familyLifetime ?? new DateInterval('P90D'),
        );
    }
}
