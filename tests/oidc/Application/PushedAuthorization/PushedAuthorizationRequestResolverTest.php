<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\PushedAuthorization;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use DateInterval;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationRequestResolver;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPushedAuthorizationRecordRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\PushedRequestRefusalReason;
use Beffroi\Oidc\Domain\Event\PushedRequestRefused;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Beffroi\Oidc\Exception\InvalidRequestUriException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class PushedAuthorizationRequestResolverTest extends TestCase
{
    private const string REFUSED = 'invalid_request_uri: The request_uri parameter names no request this provider is holding for this client (RFC 9126 section 4).';

    private Tenant $tenant;

    private RequestContext $context;

    private Client $client;

    private InMemoryPushedAuthorizationRecordRepository $requests;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PushedAuthorizationRequestResolver $resolver;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->context = Fixtures::context();
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->requests = new InMemoryPushedAuthorizationRecordRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-22T12:00:00+00:00');
        $this->resolver = new PushedAuthorizationRequestResolver($this->requests, $this->clock, $this->events);
    }

    /**
     * An ordinary authorization request carries no reference, and what it carries stands.
     */
    #[Test]
    public function aRequestThatWasNotPushedIsLeftAlone(): void
    {
        // When / Then
        static::assertNull($this->resolver->resolve(
            $this->tenant,
            [
                'client_id' => 'oidc-demo',
                'scope' => 'openid',
            ],
            $this->context,
        ));
    }

    /**
     * OIDC Core §6.2: a "request_uri" of another shape is a request object by reference, which the
     * authorization endpoint answers for; nothing here looks it up, and nothing fetches it.
     */
    #[Test]
    #[DataProvider('provideForeignReferences')]
    public function aReferenceThatIsNotOursIsLeftToTheAuthorizationEndpoint(string $requestUri): void
    {
        // When / Then
        static::assertNull($this->resolver->resolve(
            $this->tenant,
            [
                'client_id' => 'oidc-demo',
                'request_uri' => $requestUri,
            ],
            $this->context,
        ));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideForeignReferences(): iterable
    {
        yield 'an https URL' => ['https://client.example/request.jwt'];
        yield 'the prefix alone' => [RequestUri::URN_PREFIX];
    }

    /**
     * RFC 9126 §4: the parameters of the record are the request, and every other parameter of the query
     * is dropped, as it is for a request object (OIDC Core §6.1).
     */
    #[Test]
    public function theParametersOfTheRecordReplaceTheOnesOfTheQuery(): void
    {
        // Given
        $requestUri = $this->push([
            'scope' => 'openid profile',
            'state' => 'pushed-state',
        ]);

        // When
        $record = $this->resolver->resolve(
            $this->tenant,
            [
                'client_id' => 'oidc-demo',
                'request_uri' => $requestUri->value,
                'scope' => 'openid banking',
                'state' => 'query-state',
                'prompt' => 'none',
            ],
            $this->context,
        );

        // Then
        static::assertInstanceOf(PushedAuthorizationRecord::class, $record);
        static::assertSame(
            [
                'scope' => 'openid profile',
                'state' => 'pushed-state',
                'client_id' => 'oidc-demo',
            ],
            PushedAuthorizationRequestResolver::parametersOf($record),
        );
    }

    /**
     * FAPI 2.0 Security Profile §5.3.1: the reference is spent when the request it carries is granted,
     * which the authorization endpoint does, and reading it again before that is a user who came back to
     * a page nobody has answered yet.
     */
    #[Test]
    public function aReferenceIsReadAgainUntilItIsSpent(): void
    {
        // Given
        $requestUri = $this->push();
        $this->resolver->resolve($this->tenant, self::query($requestUri), $this->context);

        // When
        $record = $this->resolver->resolve($this->tenant, self::query($requestUri), $this->context);

        // Then
        static::assertInstanceOf(PushedAuthorizationRecord::class, $record);
    }

    /**
     * RFC 9126 §4: once spent, it grants nothing.
     */
    #[Test]
    public function aReferenceThatWasSpentIsRefused(): void
    {
        // Given
        $requestUri = $this->push();
        $record = $this->resolver->resolve($this->tenant, self::query($requestUri), $this->context) ?? static::fail('The reference was not read back.');
        $this->requests->consume($record, $this->clock->now());

        // Then
        $this->expectException(InvalidRequestUriException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->resolver->resolve($this->tenant, self::query($requestUri), $this->context);
    }

    /**
     * RFC 9126 §4: "An expired request_uri MUST be rejected as invalid".
     */
    #[Test]
    public function anExpiredReferenceIsRefused(): void
    {
        // Given
        $requestUri = $this->push();
        $this->clock->modify('+61 seconds');

        // Then
        $this->expectException(InvalidRequestUriException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->resolver->resolve($this->tenant, self::query($requestUri), $this->context);
    }

    /**
     * RFC 9126 §2.2: "The request_uri value MUST be bound to the client that posted the authorization
     * request".
     */
    #[Test]
    public function aReferencePushedByOneClientIsRefusedToAnother(): void
    {
        // Given
        $requestUri = $this->push();

        // Then
        $this->expectException(InvalidRequestUriException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->resolver->resolve(
            $this->tenant,
            [
                'client_id' => 'spa',
                'request_uri' => $requestUri->value,
            ],
            $this->context,
        );
    }

    /**
     * The audit trail says which client presented the reference and which one pushed it; the client
     * reads the one error of the four.
     */
    #[Test]
    public function theEventSaysWhichClientPushedTheReferenceAndWhichPresentedIt(): void
    {
        // Given
        $requestUri = $this->push();

        // When
        try {
            $this->resolver->resolve(
                $this->tenant,
                [
                    'client_id' => 'spa',
                    'request_uri' => $requestUri->value,
                ],
                $this->context,
            );
        } catch (InvalidRequestUriException) {
        }

        // Then
        $event = $this->events->of(PushedRequestRefused::class)[0] ?? null;
        static::assertSame(PushedRequestRefusalReason::OtherClient, $event?->reason);
        static::assertSame('spa', $event->presentedBy);
        static::assertSame('oidc-demo', $event->pushedBy);
        static::assertSame($this->tenant, $event->tenant);
    }

    /**
     * A reference nobody ever issued, one that is past its lifetime and one already used are one answer
     * to the client and three reasons in the audit trail.
     */
    #[Test]
    #[DataProvider('provideRefusals')]
    public function everyRefusalNamesItsReasonInTheAuditTrail(string $case, PushedRequestRefusalReason $reason): void
    {
        // Given
        $requestUri = $this->referenceThatIs($case);

        // When
        try {
            $this->resolver->resolve($this->tenant, self::query($requestUri), $this->context);
        } catch (InvalidRequestUriException) {
        }

        // Then
        static::assertSame($reason, ($this->events->of(PushedRequestRefused::class)[0] ?? null)?->reason);
    }

    /**
     * @return iterable<string, array{string, PushedRequestRefusalReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'a reference nobody issued' => ['unknown', PushedRequestRefusalReason::Unknown];
        yield 'a reference past its lifetime' => ['expired', PushedRequestRefusalReason::Expired];
        yield 'a reference already used' => ['used', PushedRequestRefusalReason::AlreadyUsed];
    }

    /**
     * A record of another tenant is a record of another provider: it is not found, and the reason says
     * the reference is not this client's.
     */
    #[Test]
    public function aReferenceOfAnotherTenantIsRefused(): void
    {
        // Given
        $requestUri = $this->push();

        // Then
        $this->expectException(InvalidRequestUriException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->resolver->resolve(Fixtures::tenant('other', 'https://id.other.example'), self::query($requestUri), $this->context);
    }

    /**
     * A reference in the state the case names: never issued, past its lifetime, or already used.
     */
    private function referenceThatIs(string $case): RequestUri
    {
        if ($case === 'unknown') {
            return RequestUri::of(Secrets::draw());
        }
        $requestUri = $this->push();
        if ($case === 'expired') {
            $this->clock->modify('+61 seconds');
        }
        if ($case === 'used') {
            // spent by the authorization endpoint that granted the request it carried, which is the one
            // thing that spends a reference (FAPI 2.0 Security Profile §5.3.1)
            $record =
                $this->requests->findByRequestUriHash(RequestUri::hashOf($requestUri->value)) ?? static::fail('The record of the reference was not stored.');
            $this->requests->consume($record, $this->clock->now());
        }

        return $requestUri;
    }

    /**
     * @param array<string, string> $parameters
     */
    private function push(array $parameters = [
        'scope' => 'openid',
    ]): RequestUri
    {
        $requestUri = RequestUri::of(Secrets::draw());
        $this->requests->save(new PushedAuthorizationRecord(
            $requestUri->hash(),
            $this->client,
            $parameters,
            $this->clock->now(),
            $this->clock->now()->add(new DateInterval('PT60S')),
        ));

        return $requestUri;
    }

    /**
     * @return array<string, string>
     */
    private static function query(RequestUri $requestUri): array
    {
        return [
            'client_id' => 'oidc-demo',
            'request_uri' => $requestUri->value,
        ];
    }
}
