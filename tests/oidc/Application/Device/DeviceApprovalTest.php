<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Device;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Oidc\Application\Consent\ConsentGranting;
use Beffroi\Oidc\Application\Device\DeviceApproval;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDeviceAuthorizationRecordRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8628 §3.3, §5.1: what the page a user goes to asks of the provider. A code that names no request
 * awaiting an answer is one refusal whatever the reason, so that a code tried at random teaches nothing.
 */
final class DeviceApprovalTest extends TestCase
{
    private const string CODE = 'BCDFGHJK';

    private Tenant $tenant;

    private Client $client;

    private AuthenticationSession $session;

    private RequestContext $context;

    private InMemoryDeviceAuthorizationRecordRepository $records;

    private InMemoryConsentRepository $consents;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private DeviceApproval $approval;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::appliance($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->clock = new MockClock('2026-09-26T09:00:00+00:00');
        $this->session = Fixtures::session(Fixtures::user($this->tenant), $this->clock->now());
        $this->context = Fixtures::context($this->clock->now());
        $this->records = new InMemoryDeviceAuthorizationRecordRepository();
        $this->consents = new InMemoryConsentRepository();
        $this->events = new RecordingEventDispatcher();
        $this->approval = new DeviceApproval(
            $this->records,
            new ConsentGranting($this->consents, new SymfonyUuidGenerator(), $this->events),
            $this->clock,
        );
    }

    /**
     * RFC 8628 §6.1: the code is looked up as the user typed it, separators and case included.
     */
    #[Test]
    #[DataProvider('provideCodesAsTheyAreTyped')]
    public function itFindsTheRequestWhateverWayTheCodeWasTyped(string $typed): void
    {
        // Given
        $record = $this->record();

        // When
        $found = $this->approval->awaitingAnAnswer($this->tenant, $typed);

        // Then
        static::assertSame($record, $found);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCodesAsTheyAreTyped(): iterable
    {
        yield 'as it was shown' => ['BCDF-GHJK'];
        yield 'bare' => ['BCDFGHJK'];
        yield 'in lower case' => ['bcdf-ghjk'];
        yield 'with spaces around it' => [' BCDF GHJK '];
    }

    /**
     * RFC 8628 §5.1: one refusal for every reason a code names no request awaiting an answer, so that a code
     * tried at random teaches nothing.
     */
    #[Test]
    #[DataProvider('provideCodesThatNameNothingToAnswer')]
    public function aCodeThatNamesNoRequestAwaitingAnAnswerFindsNothing(string $state): void
    {
        // Given
        $record = $this->record();
        match ($state) {
            'expired' => $this->clock->modify('+601 seconds'),
            'approved' => $this->approval->approve($record, $this->session, $this->context),
            'refused' => $this->approval->deny($record),
            'spent' => $record->consume($this->clock->now()),
            default => null,
        };

        // When
        $found = $this->approval->awaitingAnAnswer($this->tenant, $state === 'unknown' ? 'ZXWVTSRQ' : self::CODE);

        // Then
        static::assertNull($found);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCodesThatNameNothingToAnswer(): iterable
    {
        yield 'a code nobody ever issued' => ['unknown'];
        yield 'a code past its lifetime' => ['expired'];
        yield 'a code already approved' => ['approved'];
        yield 'a code already refused' => ['refused'];
        yield 'a code already spent' => ['spent'];
    }

    /**
     * A value that is not a code of this provider reaches no store: a form filled with anything is refused
     * before a lookup is made on it.
     */
    #[Test]
    #[DataProvider('provideValuesThatAreNotACode')]
    public function aValueThatIsNotACodeOfThisProviderFindsNothing(string $typed): void
    {
        // Given
        $this->record();

        // When
        $found = $this->approval->awaitingAnAnswer($this->tenant, $typed);

        // Then
        static::assertNull($found);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesThatAreNotACode(): iterable
    {
        yield 'nothing' => [''];
        yield 'too short' => ['BCDFGHJ'];
        yield 'a character of no alphabet of ours' => ['BCDFGHJ1'];
        yield 'a whole sentence' => ['give me a token please'];
    }

    /**
     * A request of one tenant is unknown to another, code and all.
     */
    #[Test]
    public function aRequestOfAnotherTenantIsUnknown(): void
    {
        // Given
        $this->record();

        // When
        $found = $this->approval->awaitingAnAnswer(Fixtures::tenant('other', 'https://other.test'), self::CODE);

        // Then
        static::assertNull($found);
    }

    /**
     * RFC 8628 §3.3: approving records the consent where every consent is recorded, freezes the session on
     * the record and saves it, so the client learns it at its next poll.
     */
    #[Test]
    public function approvingRecordsTheConsentAndFreezesTheSession(): void
    {
        // Given
        $record = $this->record();

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        static::assertTrue($record->isApproved());
        static::assertSame($this->session, $record->session);
        $consent = $this->consents->findActive($this->session->user, $this->client) ?? static::fail('The approval recorded no consent.');
        static::assertTrue($consent->scopes->covers($record->scopes));
    }

    /**
     * Architecture §4.3: what a user agreed to is announced once, with the context of the request that
     * agreed.
     */
    #[Test]
    public function theConsentIsAnnouncedOnceWithTheRequestContext(): void
    {
        // Given
        $record = $this->record();

        // When
        $this->approval->approve($record, $this->session, $this->context);

        // Then
        $granted = $this->events->of(ConsentGranted::class);
        static::assertCount(1, $granted);
        static::assertSame($this->context, $granted[0]->context);
    }

    /**
     * RFC 8628 §3.5: a refusal ends the request and leaves no consent behind.
     */
    #[Test]
    public function refusingEndsTheRequestAndRecordsNoConsent(): void
    {
        // Given
        $record = $this->record();

        // When
        $this->approval->deny($record);

        // Then
        static::assertTrue($record->isDenied());
        static::assertEquals($this->clock->now(), $record->deniedAt);
        static::assertNull($this->consents->findActive($this->session->user, $this->client));
        static::assertSame([], $this->events->of(ConsentGranted::class));
    }

    private function record(): DeviceAuthorizationRecord
    {
        $record = new DeviceAuthorizationRecord(
            DrawnSecret::digestOf('the-device-code'),
            UserCode::hashOf(self::CODE),
            Uuid::v7(),
            $this->client,
            new Scopes([new Scope('openid'), new Scope('profile')]),
            null,
            $this->context,
            $this->clock->now(),
            $this->clock->now()->modify('+600 seconds'),
        );
        $this->records->save($record);

        return $record;
    }
}
