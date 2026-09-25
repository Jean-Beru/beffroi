<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Ciba;

use DateTimeImmutable;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Ciba\BackchannelApproval;
use Heidi\Oidc\Application\Consent\ConsentGranting;
use Heidi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Ciba\BindingMessage;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Heidi\Oidc\Domain\Event\ConsentGranted;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeSecretSealer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * CIBA Core §10.1, §11, BCP 10027 §5.2: what the page where a user answers asks of the provider. What is
 * waiting is found by who is signed in, and a request of somebody else is not in that list and is not
 * answerable.
 */
final class BackchannelApprovalTest extends TestCase
{
    private const string AUTH_REQUEST_ID = 'the-auth-req-id';

    private Tenant $tenant;

    private Client $client;

    private User $alice;

    private AuthenticationSession $session;

    private RequestContext $context;

    private InMemoryBackchannelAuthenticationRecordRepository $records;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private BackchannelApproval $approval;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::backchannel($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->alice = Fixtures::user($this->tenant);
        $this->session = Fixtures::session($this->alice, $this->clock->now());
        $this->context = Fixtures::context($this->clock->now());
        $this->records = new InMemoryBackchannelAuthenticationRecordRepository();
        $this->events = new RecordingEventDispatcher();
        $this->approval = new BackchannelApproval(
            $this->records,
            new ConsentGranting(new InMemoryConsentRepository(), new SymfonyUuidGenerator(), $this->events),
            new FakeSecretSealer(),
            $this->events,
            $this->clock,
        );
    }

    /**
     * §10.1: what is waiting for this user, and nothing that is waiting for somebody else.
     */
    #[Test]
    public function itShowsTheRequestsMadeForThatUser(): void
    {
        // Given
        $this->records->save($this->record());
        $this->records->save($this->record('for-bob', Fixtures::user($this->tenant, 'bob', 'bob-subject')));

        // When
        $waiting = $this->approval->awaitingAnAnswerBy($this->alice);

        // Then
        static::assertCount(1, $waiting);
        static::assertSame(DrawnSecret::digestOf(self::AUTH_REQUEST_ID), $waiting[0]->authRequestIdHash);
    }

    /**
     * A request that was answered, that expired or that was spent is waiting for nobody.
     */
    #[Test]
    public function aRequestThatIsNoLongerWaitingIsNotShown(): void
    {
        // Given
        $answered = $this->record('answered');
        $answered->deny($this->clock->now());
        $this->records->save($answered);
        $spent = $this->record('spent');
        $spent->consume($this->clock->now());
        $this->records->save($spent);
        $this->records->save($this->record('expired', expiresAt: $this->clock->now()->modify('+1 second')));
        $this->clock->modify('+2 seconds');

        // When
        $waiting = $this->approval->awaitingAnAnswerBy($this->alice);

        // Then
        static::assertSame([], $waiting);
    }

    /**
     * A handle is looked for among the requests that user may answer, so a request of somebody else is
     * named by nothing.
     */
    #[Test]
    public function aHandleNamesOnlyARequestThatUserMayAnswer(): void
    {
        // Given
        $this->records->save($this->record('for-bob', Fixtures::user($this->tenant, 'bob', 'bob-subject')));

        // When
        $record = $this->approval->awaitingAnAnswerFrom($this->alice, DrawnSecret::digestOf('for-bob'));

        // Then
        static::assertNull($record);
    }

    /**
     * §10.1: approving is granting an authorization of the ordinary kind, with the consent recorded where
     * a consent is recorded and the session frozen on the record.
     */
    #[Test]
    public function anApprovalRecordsAConsentAndFreezesTheSession(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertTrue($record->isApproved());
        static::assertSame($this->session, $record->session);
        static::assertNotNull($record->authentication);
        static::assertInstanceOf(ConsentGranted::class, $this->events->events[0] ?? null);
    }

    /**
     * §7.1: only the user the request named may answer it.
     */
    #[Test]
    public function aSessionOfSomebodyElseApprovesNothing(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);
        $bob = Fixtures::session(Fixtures::user($this->tenant, 'bob', 'bob-subject'), $this->clock->now());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->approval->approve($record, $bob, $this->context);
    }

    /**
     * §11: a refusal is an answer and ends the request.
     */
    #[Test]
    public function aRefusalEndsTheRequest(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);

        // When
        $this->approval->deny($record, $this->context);

        // Then
        static::assertTrue($record->isDenied());
        static::assertSame([], $this->approval->awaitingAnAnswerBy($this->alice));
    }

    /**
     * §10.1: a client that only polls is told nothing; it finds the answer at the token endpoint.
     */
    #[Test]
    public function aPollingClientIsNotCalledBack(): void
    {
        // Given
        $record = $this->record();
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertSame(
            [],
            array_values(array_filter(
                $this->events->events,
                static fn (object $event): bool => $event instanceof BackchannelRequestAnswered,
            )),
        );
    }

    /**
     * §10.2: a client that registered to be called back is told that the request is over, with the
     * identifier it was handed and the token it sent, both read back out of their envelopes.
     */
    #[Test]
    public function aPingedClientIsToldTheRequestIsOver(): void
    {
        // Given
        $record = $this->pingedRecord();
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        $answered = $this->answeredEvent();
        static::assertSame('payment-terminal', $answered->clientId);
        static::assertSame(Clients::NOTIFICATION_ENDPOINT, $answered->notificationEndpoint->value);
        static::assertSame(self::AUTH_REQUEST_ID, $answered->authRequestId);
        static::assertSame('the-notification-token', $answered->notificationToken);
    }

    /**
     * §10.2: the client is told that the request is over whichever way it was answered; what it was
     * answered, it reads at the token endpoint.
     */
    #[Test]
    public function aPingedClientIsAlsoToldOfARefusal(): void
    {
        // Given
        $record = $this->pingedRecord();
        $this->records->save($record);

        // When
        $this->approval->deny($record, $this->context);

        // Then
        static::assertSame(self::AUTH_REQUEST_ID, $this->answeredEvent()->authRequestId);
    }

    private function answeredEvent(): BackchannelRequestAnswered
    {
        foreach ($this->events->events as $event) {
            if ($event instanceof BackchannelRequestAnswered) {
                return $event;
            }
        }

        static::fail('The client was never told the request was over.');
    }

    private function pingedRecord(): BackchannelAuthenticationRecord
    {
        $sealer = new FakeSecretSealer();
        $client = Clients::pinged($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));

        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf(self::AUTH_REQUEST_ID),
            $client,
            $this->alice,
            new Scopes([Scope::openid()]),
            null,
            new BindingMessage('Payment of 42 euros'),
            $sealer->seal($this->tenant, self::AUTH_REQUEST_ID),
            $sealer->seal($this->tenant, 'the-notification-token'),
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+300 seconds'),
        );
    }

    private function record(
        string $authRequestId = self::AUTH_REQUEST_ID,
        ?User $user = null,
        ?DateTimeImmutable $expiresAt = null,
    ): BackchannelAuthenticationRecord {
        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf($authRequestId),
            $this->client,
            $user ?? $this->alice,
            new Scopes([Scope::openid()]),
            null,
            null,
            null,
            null,
            $this->context,
            $this->clock->now(),
            $expiresAt ?? $this->clock->now()->modify('+300 seconds'),
        );
    }
}
