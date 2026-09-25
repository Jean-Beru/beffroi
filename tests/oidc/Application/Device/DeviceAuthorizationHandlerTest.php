<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Device;

use function array_filter;
use function array_merge;
use function base64_encode;
use DateInterval;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Device\DeviceAuthorizationHandler;
use Heidi\Oidc\Application\Secret\UserCodeDrawer;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationResponse;
use Heidi\Oidc\Domain\Device\UserCode;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\InvalidTargetException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Endpoints;
use Heidi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Methods;
use Heidi\Oidc\Tests\Fixture\Secrets;
use Heidi\Oidc\Tests\Fixture\UserCodes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function urlencode;

/**
 * RFC 8628 §3.1, §3.2: an authenticated client asks, and is answered two codes, where its user goes, for how
 * long and how often it may ask.
 */
final class DeviceAuthorizationHandlerTest extends TestCase
{
    private const string FIRST_CODE = 'BCDFGHJK';

    private const string SECOND_CODE = 'LMNPQRST';

    private Tenant $tenant;

    private RequestContext $context;

    private FakePasswordHasher $hasher;

    private InMemoryClientRepository $clients;

    private InMemoryDeviceAuthorizationRecordRepository $records;

    private MockClock $clock;

    private DeviceAuthorizationHandler $handler;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
        $this->hasher = new FakePasswordHasher();
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(Clients::appliance($this->tenant, $this->hasher->hash(Clients::SECRET)));
        $this->clients->save(Clients::appliance(
            $this->tenant,
            $this->hasher->hash(Clients::SECRET),
            'television-with-resources',
            resources: Clients::resources(),
        ));
        $this->clients->save(Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET)));
        $this->records = new InMemoryDeviceAuthorizationRecordRepository();
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->handler = $this->handler();
    }

    /**
     * RFC 8628 §3.2: the two codes, the page the user goes to, the same page with the code already in it
     * (§3.3.1), the lifetime and the interval.
     */
    #[Test]
    public function itAnswersTheCodesThePageAndTheTimes(): void
    {
        // When
        $response = $this->ask();

        // Then
        static::assertTrue(DrawnSecret::isValue($response->deviceCode));
        static::assertSame(self::FIRST_CODE, $response->userCode->value);
        static::assertSame('https://id.acme.example/device', $response->verificationUri);
        static::assertSame(600, $response->expiresIn);
        static::assertSame(5, $response->interval);
    }

    /**
     * RFC 8628 §3.2: the record waits under the hash of the device code, bound to the client that asked,
     * with what the request asked for, unanswered and unspent.
     */
    #[Test]
    public function itKeepsTheRequestUnderTheHashOfItsDeviceCode(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record =
            $this->records->findByDeviceCodeHash(DrawnSecret::digestOf($response->deviceCode)) ?? static::fail('The endpoint kept no record for the code it answered with.');
        static::assertSame('television', $record->clientId);
        static::assertSame($this->tenant, $record->tenant);
        static::assertSame('openid profile', (string) $record->scopes);
        static::assertFalse($record->isAnswered());
        static::assertFalse($record->isUsed());
    }

    /**
     * The page the user types on looks a code up by itself, so the record is found by the user code too.
     */
    #[Test]
    public function theRecordIsFoundByTheCodeTheUserTypes(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record = $this->records->findByUserCodeHash($response->userCode->hash()) ?? static::fail('The endpoint kept no record for the code it showed.');
        static::assertSame(DrawnSecret::digestOf($response->deviceCode), $record->deviceCodeHash);
    }

    /**
     * What the provider keeps is the digest of both codes and never their value, as of every other value it
     * hands out.
     */
    #[Test]
    public function itKeepsTheDigestOfBothCodesAndNeitherValue(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record = $this->records->findByDeviceCodeHash(DrawnSecret::digestOf($response->deviceCode)) ?? static::fail('No record.');
        static::assertTrue(DrawnSecret::isDigest($record->deviceCodeHash));
        static::assertTrue(DrawnSecret::isDigest($record->userCodeHash));
        static::assertNotSame($response->deviceCode, $record->deviceCodeHash);
        static::assertNotSame($response->userCode->value, $record->userCodeHash);
    }

    /**
     * BCP 10027 §2: the approval page says where the request came from, so the record keeps it.
     */
    #[Test]
    public function itKeepsWhereTheApplianceAskedFrom(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record = $this->records->findByDeviceCodeHash(DrawnSecret::digestOf($response->deviceCode)) ?? static::fail('No record.');
        static::assertSame($this->context->ipAddress, $record->requestedFrom->ipAddress);
        static::assertSame($this->context->userAgent, $record->requestedFrom->userAgent);
    }

    /**
     * RFC 8707 §2: the resources the request names, among the ones the client registered.
     */
    #[Test]
    public function theTokenIsAddressedToTheResourceTheRequestNames(): void
    {
        // When
        $response = $this->askAs('television-with-resources', [
            'resource' => Clients::CALENDAR,
        ]);

        // Then
        $record = $this->records->findByDeviceCodeHash(DrawnSecret::digestOf($response->deviceCode)) ?? static::fail('No record.');
        static::assertEquals([new ResourceIndicator(Clients::CALENDAR)], $record->resources?->all);
    }

    /**
     * RFC 8707 §2: a request that names no resource is served all the same, there being a user behind this
     * grant and therefore a client the token can be addressed to.
     */
    #[Test]
    public function aRequestThatNamesNoResourceIsServed(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record = $this->records->findByDeviceCodeHash(DrawnSecret::digestOf($response->deviceCode)) ?? static::fail('No record.');
        static::assertNull($record->resources);
    }

    /**
     * RFC 8628 §3.1: the endpoint serves the clients registered for a grant that asks their user on another
     * device, and no other. Which grants those are is read from the wiring and never from a name.
     */
    #[Test]
    public function itRefusesAClientWhoseGrantsTakeNoUserOnAnotherDevice(): void
    {
        // Then
        $this->expectException(UnauthorizedClientException::class);
        $this->expectExceptionMessageIsOrContains('not registered for a grant that asks its user on another device');

        // When
        $this->askAs('oidc-demo');
    }

    /**
     * RFC 6749 §2.3: the client of the request is authenticated before anything is read of what it asks.
     */
    #[Test]
    public function itAuthenticatesTheClientBeforeReadingTheRequest(): void
    {
        // Then
        $this->expectException(InvalidClientException::class);

        // When
        $this->handler->handle($this->tenant, self::basic('television', 'the-wrong-secret'), [], $this->context);
    }

    /**
     * A request the endpoint refuses leaves nothing behind for anybody to approve.
     *
     * @param array<string, string|null> $overrides
     * @param class-string<OAuth2Exception> $error
     */
    #[Test]
    #[DataProvider('provideRequestsThisEndpointRefuses')]
    public function aRequestThisEndpointRefusesKeepsNoRecord(string $clientId, array $overrides, string $error): void
    {
        // Given
        $this->expectException($error);

        // When
        try {
            $this->askAs($clientId, $overrides);
        } finally {
            // Then
            static::assertNull($this->records->findByUserCodeHash(UserCode::hashOf(self::FIRST_CODE)));
        }
    }

    /**
     * @return iterable<string, array{string, array<string, string|null>, class-string<OAuth2Exception>}>
     */
    public static function provideRequestsThisEndpointRefuses(): iterable
    {
        yield 'no scope (RFC 6749 §3.3)' => ['television', ['scope' => null], InvalidRequestException::class];
        yield 'a scope the client did not register' => ['television', ['scope' => 'payroll.read'], InvalidScopeException::class];
        yield 'a scope that is not a scope token' => ['television', ['scope' => "openid\tprofile"], InvalidScopeException::class];
        yield 'a resource the client did not register (RFC 8707 §2.1)' => [
            'television-with-resources',
            ['resource' => 'https://files.example.com/'],
            InvalidTargetException::class,
        ];
        yield 'a resource that is not an absolute URI' => ['television-with-resources', ['resource' => '/calendar'], InvalidTargetException::class];
        yield 'a resource of a client that registered none' => ['television', ['resource' => Clients::CALENDAR], InvalidTargetException::class];
    }

    /**
     * A code the store already holds is drawn again: the page looks a code up by itself, so two live records
     * carrying the same one would be two requests one answer could approve.
     */
    #[Test]
    public function itDrawsAgainWhenTheCodeItDrewIsOneItAlreadyHolds(): void
    {
        // Given
        $first = $this->ask();

        // When
        $second = $this->handler(UserCodes::drawer([$first->userCode->value, self::SECOND_CODE]))->handle(
            $this->tenant,
            self::basic('television', Clients::SECRET),
            self::parameters([]),
            $this->context,
        );

        // Then
        static::assertSame(self::SECOND_CODE, $second->userCode->value);
    }

    /**
     * The lifetime and the interval are the deployment's, and what the client is told is what the record has.
     */
    #[Test]
    public function theLifetimeAndTheIntervalAreTheOnesTheDeploymentWired(): void
    {
        // Given
        $handler = $this->handler(lifetime: new DateInterval('PT300S'), interval: 7);

        // When
        $response = $handler->handle($this->tenant, self::basic('television', Clients::SECRET), self::parameters([]), $this->context);

        // Then
        static::assertSame(300, $response->expiresIn);
        static::assertSame(7, $response->interval);
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function ask(array $overrides = []): DeviceAuthorizationResponse
    {
        return $this->askAs('television', $overrides);
    }

    /**
     * @param array<string, string|null> $overrides
     */
    private function askAs(string $clientId, array $overrides = []): DeviceAuthorizationResponse
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
            array_merge(['scope' => 'openid profile'], $overrides),
            static fn (mixed $value): bool => $value !== null,
        );
    }

    /**
     * @param positive-int|null $interval
     */
    private function handler(?UserCodeDrawer $userCodes = null, ?DateInterval $lifetime = null, ?int $interval = null): DeviceAuthorizationHandler
    {
        return new DeviceAuthorizationHandler(
            new ClientAuthenticator(
                $this->clients,
                Methods::all($this->hasher),
                Methods::requestParser(),
                $this->clock,
                new RecordingEventDispatcher(),
                new FakeClientLoadBudget(),
            ),
            new Endpoints(),
            Grants::servedWithDeviceCode(),
            $this->records,
            Secrets::drawer(),
            $userCodes ?? UserCodes::drawer([self::FIRST_CODE, self::SECOND_CODE]),
            $this->clock,
            $lifetime ?? new DateInterval('PT600S'),
            $interval ?? 5,
        );
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($secret));
    }
}
