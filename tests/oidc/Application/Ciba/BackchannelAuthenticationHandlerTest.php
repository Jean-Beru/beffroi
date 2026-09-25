<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Ciba;

use function array_filter;
use function array_merge;
use function base64_encode;
use DateInterval;
use Heidi\Core\Bridge\InMemory\InMemoryUserRepository;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Ciba\BackchannelAuthenticationHandler;
use Heidi\Oidc\Application\Ciba\Hint\SubjectLoginHint;
use Heidi\Oidc\Application\Ciba\UserHints;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationResponse;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidBindingMessageException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\InvalidTargetException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Endpoints;
use Heidi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Heidi\Oidc\Tests\Fixture\FakeSecretSealer;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\RecordingPendingApprovalNotifier;
use Heidi\Oidc\Tests\Fixture\RequestObjects;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * CIBA Core §7: an authenticated client asks for a user it names, and is answered an identifier, a
 * lifetime and an interval, whoever that user turns out to be.
 */
final class BackchannelAuthenticationHandlerTest extends TestCase
{
    private Tenant $tenant;

    private RequestContext $context;

    private FakePasswordHasher $hasher;

    private InMemoryClientRepository $clients;

    private InMemoryUserRepository $users;

    private InMemoryBackchannelAuthenticationRecordRepository $records;

    private RecordingPendingApprovalNotifier $notifier;

    private MockClock $clock;

    private BackchannelAuthenticationHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
        $this->hasher = new FakePasswordHasher();
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(Clients::backchannel($this->tenant, $this->hasher->hash(Clients::SECRET)));
        $this->clients->save(Clients::pinged($this->tenant, $this->hasher->hash(Clients::SECRET), 'pinged-terminal'));
        $this->clients->save(Clients::backchannel(
            $this->tenant,
            $this->hasher->hash(Clients::SECRET),
            'terminal-with-resources',
            resources: Clients::resources(),
        ));
        $this->clients->save(Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET)));
        $this->clients->save(Clients::backchannel(
            $this->tenant,
            $this->hasher->hash(Clients::SECRET),
            'terminal-without-a-mode',
            delivery: null,
        ));
        $this->users = new InMemoryUserRepository();
        $this->users->save(Fixtures::user($this->tenant));
        $this->records = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->notifier = new RecordingPendingApprovalNotifier();
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->handler = $this->handler();
    }

    /**
     * §7.3: the identifier, the lifetime and the interval.
     */
    #[Test]
    public function itAnswersAnIdentifierALifetimeAndAnInterval(): void
    {
        // When
        $response = $this->ask();

        // Then
        static::assertTrue(DrawnSecret::isValue($response->authRequestId));
        static::assertSame(300, $response->expiresIn);
        static::assertSame(5, $response->interval);
    }

    /**
     * §7: the record waits under the hash of the identifier, bound to the client that asked and to the
     * user it named, with what the request asked for, unanswered and unspent.
     */
    #[Test]
    public function itKeepsTheRequestUnderTheHashOfItsIdentifier(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record =
            $this->records->findByAuthRequestIdHash(DrawnSecret::digestOf($response->authRequestId)) ?? static::fail('The endpoint kept no record for the identifier it answered with.');
        static::assertSame('payment-terminal', $record->clientId);
        static::assertSame($this->tenant, $record->tenant);
        static::assertSame('alice', $record->user?->username);
        static::assertSame('openid profile', (string) $record->scopes);
        static::assertFalse($record->isAnswered());
        static::assertFalse($record->isUsed());
    }

    /**
     * What the provider keeps of a client that only polls is the digest of the identifier and nothing
     * else: that client is the only holder of the value, as of every other value this provider draws.
     */
    #[Test]
    public function aPollingClientLeavesNothingBehindButADigest(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record = $this->records->findByAuthRequestIdHash(DrawnSecret::digestOf($response->authRequestId)) ?? static::fail('No record.');
        static::assertNull($record->sealedAuthRequestId);
        static::assertNull($record->sealedNotificationToken);
    }

    /**
     * §10.2: a client this provider has to call back is the one reason it keeps what it handed out, and
     * both values are kept sealed under the KMS of the tenant.
     */
    #[Test]
    public function aClientThatIsCalledBackLeavesTwoSealedValues(): void
    {
        // When
        $response = $this->askAs('pinged-terminal', [
            'client_notification_token' => self::NOTIFICATION_TOKEN,
        ]);

        // Then
        $record = $this->records->findByAuthRequestIdHash(DrawnSecret::digestOf($response->authRequestId)) ?? static::fail('No record.');
        $sealer = new FakeSecretSealer();
        static::assertSame($response->authRequestId, $sealer->unseal($this->tenant, self::string($record->sealedAuthRequestId)));
        static::assertSame(self::NOTIFICATION_TOKEN, $sealer->unseal($this->tenant, self::string($record->sealedNotificationToken)));
    }

    /**
     * §7: the user the request named is told that something is waiting for them, with the message the
     * client wrote and the page where an answer is given, and with nothing that carries them into one.
     */
    #[Test]
    public function theUserItNamesIsToldSomethingIsWaiting(): void
    {
        // When
        $this->ask([
            'binding_message' => 'Payment of 42 euros',
        ]);

        // Then
        static::assertCount(1, $this->notifier->told);
        $approval = $this->notifier->told[0];
        static::assertSame('Payment terminal at the counter', $approval->clientName);
        static::assertSame('Payment of 42 euros', $approval->bindingMessage?->value);
        static::assertSame('https://id.acme.example/approvals', $approval->approvalUri);
        static::assertEquals($this->clock->now()->modify('+300 seconds'), $approval->expiresAt);
    }

    /**
     * Decision 0006, §13: a request naming a stranger is answered exactly as a request naming somebody
     * who never answers, and the record it leaves is answerable by nobody.
     */
    #[Test]
    public function aRequestNamingAStrangerIsAnsweredLikeEveryOther(): void
    {
        // When
        $response = $this->ask([
            'login_hint' => 'nobody-subject',
        ]);

        // Then
        static::assertTrue(DrawnSecret::isValue($response->authRequestId));
        static::assertSame(300, $response->expiresIn);
        $record = $this->records->findByAuthRequestIdHash(DrawnSecret::digestOf($response->authRequestId)) ?? static::fail('No record.');
        static::assertNull($record->user);
        static::assertSame([], $this->notifier->told, 'there is nobody to tell');
    }

    /**
     * §7.1: a client registered for none of the grants of this flow is refused here rather than answered
     * an identifier nothing would ever spend.
     */
    #[Test]
    public function aClientOfAnotherFlowIsRefused(): void
    {
        // Then
        $this->expectException(UnauthorizedClientException::class);
        $this->expectExceptionMessageIs('unauthorized_client: The client is not registered for a grant that waits for its user to approve a request made elsewhere (CIBA Core section 7.1).');

        // When
        $this->askAs('oidc-demo');
    }

    /**
     * §4: a client that registered no delivery mode is not a client of this flow, and no default makes
     * it one.
     */
    #[Test]
    public function aClientThatRegisteredNoDeliveryModeIsRefused(): void
    {
        // Then
        $this->expectException(UnauthorizedClientException::class);
        $this->expectExceptionMessageIs('unauthorized_client: The client registered no backchannel token delivery mode, and is told nothing about a request it could not be answered for (CIBA Core section 4).');

        // When
        $this->askAs('terminal-without-a-mode');
    }

    /**
     * §7.1: the request is authenticated as at the token endpoint, and nothing is read of it before that.
     */
    #[Test]
    public function anUnauthenticatedRequestIsRefused(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);

        // When
        $this->handler->handle($this->tenant, self::basic('payment-terminal', 'the-wrong-secret'), self::parameters([]), $this->context);
    }

    /**
     * §7.1: "openid" is among the scopes of every request of this flow.
     */
    #[Test]
    public function aRequestThatDoesNotAskForOpenidIsRefused(): void
    {
        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIs('invalid_scope: A backchannel authentication request asks for the openid scope (CIBA Core section 7.1).');

        // When
        $this->ask([
            'scope' => 'profile',
        ]);
    }

    /**
     * RFC 6749 §3.3: among the scopes the client registered, and never more.
     */
    #[Test]
    public function aScopeTheClientDidNotRegisterIsRefused(): void
    {
        // Then
        $this->expectException(InvalidScopeException::class);
        $this->expectExceptionMessageIs('invalid_scope: The requested scope is not allowed for this client.');

        // When
        $this->ask([
            'scope' => 'openid email',
        ]);
    }

    /**
     * §7.1: a request that names no scope at all says nothing a page could show somebody.
     */
    #[Test]
    public function aRequestWithoutScopesIsRefused(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The scope parameter is missing.');

        // When
        $this->ask([
            'scope' => null,
        ]);
    }

    /**
     * §13: a message that cannot be shown as it was sent is refused with the error that says so.
     */
    #[Test]
    public function aBindingMessageThatCannotBeShownIsRefused(): void
    {
        // Then
        $this->expectException(InvalidBindingMessageException::class);
        $this->expectExceptionMessageIs('invalid_binding_message: The binding message is not one that can be shown to a user as it was sent (CIBA Core section 7.1).');

        // When
        $this->ask([
            'binding_message' => "Pay 42\nnow",
        ]);
    }

    /**
     * §7.1: the token is required of a client this provider calls back.
     */
    #[Test]
    public function aClientThatIsCalledBackSendsATokenToRecogniseTheCall(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The client_notification_token parameter is missing, and this client registered a mode where this provider calls it back (CIBA Core section 7.1).');

        // When
        $this->askAs('pinged-terminal');
    }

    /**
     * §7.1: a client that only polls sends none, and one that sends one is telling the provider to keep a
     * credential it would never present.
     */
    #[Test]
    public function aPollingClientSendsNoTokenAtAll(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The client_notification_token parameter is for a client this provider calls back, and this client registered a mode where it does not (CIBA Core section 7.1).');

        // When
        $this->ask([
            'client_notification_token' => self::NOTIFICATION_TOKEN,
        ]);
    }

    /**
     * §7.1: a token this provider could not present back is refused where it arrives.
     */
    #[Test]
    public function aTokenTheProviderCouldNotPresentBackIsRefused(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The client_notification_token parameter is not a bearer token this provider could present back (CIBA Core section 7.1).');

        // When
        $this->askAs('pinged-terminal', [
            'client_notification_token' => 'too-short',
        ]);
    }

    /**
     * §7.1: this provider does not take a user code, and the document says so; a request carrying one is
     * refused rather than served without it.
     */
    #[Test]
    public function aRequestCarryingAUserCodeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: This provider does not take a user_code on a backchannel authentication request, and says so in its metadata (CIBA Core section 7.1).');

        // When
        $this->ask([
            'user_code' => '1234',
        ]);
    }

    /**
     * §7.1: what the client asks the lifetime to be, capped at what the provider serves.
     */
    #[Test]
    #[DataProvider('provideRequestedExpiries')]
    public function theLifetimeAskedForIsServedUpToTheMaximum(string $requested, int $expected): void
    {
        // When
        $response = $this->ask([
            'requested_expiry' => $requested,
        ]);

        // Then
        static::assertSame($expected, $response->expiresIn);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideRequestedExpiries(): iterable
    {
        yield 'shorter than the default' => ['60', 60];
        yield 'longer than the default' => ['900', 900];
        yield 'longer than the maximum' => ['99999', 1800];
    }

    /**
     * §7.1: a value that is not a number of seconds is refused, a client that wrote something there
     * having meant something by it.
     */
    #[Test]
    #[DataProvider('provideRefusedExpiries')]
    public function aLifetimeThatIsNoNumberOfSecondsIsRefused(string $requested): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The requested_expiry parameter is a positive number of seconds (CIBA Core section 7.1); at most 1800 are served.');

        // When
        $this->ask([
            'requested_expiry' => $requested,
        ]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedExpiries(): iterable
    {
        yield 'zero' => ['0'];
        yield 'negative' => ['-60'];
        yield 'not a number' => ['soon'];
        yield 'a number with a unit' => ['60s'];
    }

    /**
     * RFC 8707 §2: the resources the request names are kept on the record, among the ones the client
     * registered.
     */
    #[Test]
    public function theResourcesTheRequestNamesAreKept(): void
    {
        // When
        $response = $this->askAs('terminal-with-resources', [
            'resource' => Clients::CALENDAR,
        ]);

        // Then
        $record = $this->records->findByAuthRequestIdHash(DrawnSecret::digestOf($response->authRequestId)) ?? static::fail('No record.');
        static::assertSame([Clients::CALENDAR], $record->resources?->values());
    }

    /**
     * RFC 8707 §2: a resource the client did not register is refused.
     */
    #[Test]
    public function aResourceTheClientDidNotRegisterIsRefused(): void
    {
        // Then
        $this->expectException(InvalidTargetException::class);

        // When
        $this->ask([
            'resource' => Clients::CALENDAR,
        ]);
    }

    /**
     * RFC 9101 §6.1, FAPI-CIBA §5.2.2: the request may itself be a signed object, read here against the
     * client that has just authenticated, and what it carries is the request.
     */
    #[Test]
    public function aSignedRequestObjectIsTheRequest(): void
    {
        // Given
        $this->clients->save(Clients::backchannel(
            $this->tenant,
            $this->hasher->hash(Clients::SECRET),
            'signing-terminal',
            jwks: ClientAssertions::publishedKeys(),
        ));

        // When
        $response = $this->handler->handle(
            $this->tenant,
            self::basic('signing-terminal', Clients::SECRET),
            [
                'client_id' => 'signing-terminal',
                'request' => RequestObjects::signed(RequestObjects::claims('signing-terminal', $this->tenant->issuer->value, $this->clock->now(), [
                    'scope' => 'openid profile',
                    'login_hint' => 'alice-subject',
                    'binding_message' => 'Payment of 42 euros',
                ])),
            ],
            $this->context,
        );

        // Then
        $record = $this->records->findByAuthRequestIdHash(DrawnSecret::digestOf($response->authRequestId)) ?? static::fail('No record.');
        static::assertSame('Payment of 42 euros', $record->bindingMessage?->value);
        static::assertSame('alice', $record->user?->username);
    }

    /**
     * The lifetime, the maximum and the interval are the deployment's, and what the client is told is
     * what the record has.
     */
    #[Test]
    public function theLifetimeAndTheIntervalAreTheOnesTheDeploymentWired(): void
    {
        // Given
        $handler = $this->handler(lifetime: new DateInterval('PT120S'), interval: 7);

        // When
        $response = $handler->handle($this->tenant, self::basic('payment-terminal', Clients::SECRET), self::parameters([]), $this->context);

        // Then
        static::assertSame(120, $response->expiresIn);
        static::assertSame(7, $response->interval);
    }

    private const string NOTIFICATION_TOKEN = 'a8f2c1d0e9b7a6c5d4e3f2a1b0';

    /**
     * @param array<string, string|null> $overrides
     */
    private function ask(array $overrides = []): BackchannelAuthenticationResponse
    {
        return $this->askAs('payment-terminal', $overrides);
    }

    /**
     * @param array<string, string|null> $overrides
     *
     * @throws OAuth2Exception
     */
    private function askAs(string $clientId, array $overrides = []): BackchannelAuthenticationResponse
    {
        return $this->handler->handle($this->tenant, self::basic($clientId, Clients::SECRET), self::parameters($overrides), $this->context);
    }

    /**
     * @param array<string, string|null> $overrides
     *
     * @return array<string, string>
     */
    private static function parameters(array $overrides): array
    {
        return array_filter(
            array_merge([
                'scope' => 'openid profile',
                'login_hint' => 'alice-subject',
            ], $overrides),
            static fn (mixed $value): bool => $value !== null,
        );
    }

    /**
     * @param positive-int|null $interval
     */
    private function handler(?DateInterval $lifetime = null, ?int $interval = null): BackchannelAuthenticationHandler
    {
        return new BackchannelAuthenticationHandler(
            new ClientAuthenticator(
                $this->clients,
                Methods::all($this->hasher),
                Methods::requestParser(),
                $this->clock,
                new RecordingEventDispatcher(),
                new FakeClientLoadBudget(),
            ),
            new Endpoints(),
            Grants::servedWithCiba(),
            RequestObjects::resolver($this->clients, $this->clock),
            new UserHints([new SubjectLoginHint($this->users)]),
            $this->records,
            Secrets::drawer(),
            new FakeSecretSealer(),
            $this->notifier,
            $this->clock,
            $lifetime ?? new DateInterval('PT300S'),
            new DateInterval('PT1800S'),
            $interval ?? 5,
        );
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }

    private static function string(?string $value): string
    {
        static::assertIsString($value);

        return $value;
    }
}
