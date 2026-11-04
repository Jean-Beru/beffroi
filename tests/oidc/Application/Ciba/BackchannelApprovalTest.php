<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Ciba;

use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;
use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Ciba\ApprovalAuthenticationRequirement;
use Beffroi\Oidc\Application\Ciba\BackchannelApproval;
use Beffroi\Oidc\Application\Consent\ConsentGranting;
use Beffroi\Oidc\Bridge\InMemory\InMemoryBackchannelAuthenticationRecordRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeSecretSealer;
use Beffroi\Oidc\Tests\Fixture\Logins;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §10.1, §11, BCP 10027 §5.2
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

    private InMemoryCredentialRepository $credentials;

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
        $this->credentials = new InMemoryCredentialRepository();
        $this->approval = new BackchannelApproval(
            $this->records,
            new ConsentGranting(new InMemoryConsentRepository(), new SymfonyUuidGenerator(), $this->events),
            new ApprovalAuthenticationRequirement(Logins::passwordAndPasskey(), $this->credentials),
            new FakeSecretSealer(),
            $this->events,
            $this->clock,
        );
    }

    /**
     * CIBA Core §10.1
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
     * CIBA Core §10.1
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
     * CIBA Core §7.1
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
     * CIBA Core §11
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
     * CIBA Core §10.1
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
     * CIBA Core §10.2
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
     * CIBA Core §10.2
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

    /**
     * CIBA Core §7.1
     */
    #[Test]
    public function aSessionOfSomebodyElseIsRefusedForWhoItIsAndNotForWhatItProves(): void
    {
        // Given
        $bob = Fixtures::user($this->tenant, 'bob', 'bob-subject');
        $this->credentials->save(Fixtures::passkey($bob));
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is approved by the user it named, with a session of its own tenant.');

        // When
        $this->approval->approve($record, Fixtures::session($bob, $this->clock->now()), $this->context);
    }

    /**
     * CIBA Core §7.1, Decision 0010
     */
    #[Test]
    public function aSessionThatProvesNoRequestedClassOwesOneMoreProof(): void
    {
        // Given
        $this->aliceHoldsAPasskey();
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // When
        $stepUp = $this->approval->stepUpFor($record, $this->session) ?? static::fail('The session owes no proof.');

        // Then
        static::assertSame(['phr'], array_map(static fn (AuthenticationContextClass $class): string => $class->value, $stepUp->classes));
        static::assertSame(['passkey'], $stepUp->kinds());
    }

    /**
     * CIBA Core §7.1
     */
    #[Test]
    public function anApprovalBySuchASessionIsRefused(): void
    {
        // Given
        $this->aliceHoldsAPasskey();
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A backchannel authentication request is approved by a session that proves what it asked for; the page that answers it reads stepUpFor() first.');

        // When
        $this->approval->approve($record, $this->session, $this->context);
    }

    /**
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function aClassNoCredentialOfTheUserCouldReachOwesNothing(): void
    {
        // Given
        $record = $this->record(acrValues: ['phr']);
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertTrue($record->isApproved());
        static::assertSame('1', $record->authentication?->contextClass);
    }

    /**
     * OIDC Core §2, §5.5.1.1
     */
    #[Test]
    public function theTokensNameTheRequestedClassTheSessionSatisfies(): void
    {
        // Given
        $record = $this->record(acrValues: ['phr', '1']);
        $this->records->save($record);

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertSame('1', $record->authentication?->contextClass);
    }

    private function aliceHoldsAPasskey(): PasskeyCredential
    {
        $passkey = Fixtures::passkey($this->alice);
        $this->credentials->save($passkey);

        return $passkey;
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
            Uuid::v7(),
            $client,
            $this->alice,
            new Scopes([Scope::openid()]),
            null,
            new BindingMessage('Payment of 42 euros'),
            [],
            $sealer->seal($this->tenant, self::AUTH_REQUEST_ID),
            $sealer->seal($this->tenant, 'the-notification-token'),
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+300 seconds'),
        );
    }

    /**
     * @param list<string> $acrValues
     */
    private function record(
        string $authRequestId = self::AUTH_REQUEST_ID,
        ?User $user = null,
        ?DateTimeImmutable $expiresAt = null,
        array $acrValues = [],
    ): BackchannelAuthenticationRecord {
        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf($authRequestId),
            Uuid::v7(),
            $this->client,
            $user ?? $this->alice,
            new Scopes([Scope::openid()]),
            null,
            null,
            $acrValues,
            null,
            null,
            $this->context,
            $this->clock->now(),
            $expiresAt ?? $this->clock->now()->modify('+300 seconds'),
        );
    }
}
