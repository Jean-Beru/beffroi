<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Device;

use function array_filter;
use function array_merge;
use function base64_encode;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Oidc\Application\Administration\AdministrationAudience;
use Beffroi\Oidc\Tests\Fixture\Administrations;
use DateInterval;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Device\DeviceAuthorizationHandler;
use Beffroi\Oidc\Application\Secret\UserCodeDrawer;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationResponse;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\UnauthorizedClientException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\FakeClientLoadBudget;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\UserCodes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function urlencode;

/**
 * RFC 8628 §3.1, §3.2
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

    private AdministrationAudience $administration;

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
        $this->administration = Administrations::none();
        $this->handler = $this->handler();
    }

    /**
     * RFC 8628 §3.2, §3.3.1
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
     * RFC 8628 §3.2
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

    #[Test]
    public function theRecordIsFoundByTheCodeTheUserTypes(): void
    {
        // When
        $response = $this->ask();

        // Then
        $record = $this->records->findByUserCodeHash($response->userCode->hash()) ?? static::fail('The endpoint kept no record for the code it showed.');
        static::assertSame(DrawnSecret::digestOf($response->deviceCode), $record->deviceCodeHash);
    }

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
     * BCP 10027 §2
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
     * RFC 8628 §5.4, decision 0038
     */
    #[Test]
    public function theAdministrationApiOfTheTenantIsRefused(): void
    {
        // Given
        $this->administration = Administrations::of($this->tenant, new InMemoryGroupMembershipRepository(), Clients::CALENDAR);
        $this->handler = $this->handler();

        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIs('invalid_target: The requested resource is reserved to the administrators of the tenant (RFC 8707 section 2).');

        // When
        $this->askAs('television-with-resources', [
            'resource' => Clients::CALENDAR,
        ]);
    }

    /**
     * RFC 8707 §2
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
     * RFC 8707 §2
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
     * RFC 8628 §3.1
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
     * RFC 6749 §2.3
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
     * RFC 8628 §3.5
     */
    #[Test]
    public function itIsNotBuiltWithAnIntervalNoRequestMayBeMadeWith(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A device authorization request announces a polling interval of at most 30 seconds, a client respecting it (RFC 8628 section 3.5); 31 given.');

        // When
        $this->handler(interval: DeviceAuthorizationRecord::MAX_INTERVAL + 1);
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
            new SymfonyUuidGenerator(),
            $this->administration,
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
