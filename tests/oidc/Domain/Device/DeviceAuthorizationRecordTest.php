<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Device;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8628 §3.2, §3.3, §3.5: the record waits for its user, who answers it once, and for the client, which
 * spends it once and is told to slow down when it asks faster than it was told to.
 */
final class DeviceAuthorizationRecordTest extends TestCase
{
    private Client $client;

    private AuthenticationSession $session;

    private DateTimeImmutable $issuedAt;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $this->client = Clients::appliance($tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->session = Fixtures::session(Fixtures::user($tenant));
        $this->issuedAt = new DateTimeImmutable('2026-09-26T09:00:00+00:00');
    }

    #[Test]
    public function itIsBoundToItsClientAndToTheTenantOfThatClient(): void
    {
        // When
        $record = $this->record();

        // Then
        static::assertSame('television', $record->clientId);
        static::assertSame($this->client->tenant, $record->tenant);
        static::assertTrue($record->belongsTo($this->client));
        static::assertFalse($record->isAnswered());
        static::assertFalse($record->isUsed());
    }

    /**
     * RFC 8628 §3.2: the lifetime the client is told is the one the record has, never a longer one.
     */
    #[Test]
    public function theLifetimeItAnnouncesIsTheOneItHas(): void
    {
        // Given
        $record = $this->record();

        // When / Then
        static::assertSame(600, $record->expiresIn($this->issuedAt));
        static::assertSame(1, $record->expiresIn($this->issuedAt->modify('+600 seconds')), 'never zero, never negative');
    }

    /**
     * RFC 8628 §3.3: the session the user approved with, and the class it had proven then, are frozen on
     * the record: the tokens the client polls for descend from the approval.
     */
    #[Test]
    public function anApprovalFreezesTheSessionItWasGivenWith(): void
    {
        // Given
        $record = $this->record();
        $approvedAt = $this->issuedAt->modify('+30 seconds');

        // When
        $record->approve($this->session, AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()), $approvedAt);

        // Then
        static::assertTrue($record->isApproved());
        static::assertFalse($record->isDenied());
        static::assertSame($this->session, $record->session);
        static::assertSame($this->session->methodReferences(), $record->authentication?->methods);
        static::assertEquals($approvedAt, $record->approvedAt);
    }

    /**
     * RFC 8628 §3.5: a refusal is an answer, and the client learns "access_denied" from it.
     */
    #[Test]
    public function aRefusalIsAnAnswerAndLeavesNoSession(): void
    {
        // Given
        $record = $this->record();

        // When
        $record->deny($this->issuedAt->modify('+30 seconds'));

        // Then
        static::assertTrue($record->isDenied());
        static::assertFalse($record->isApproved());
        static::assertTrue($record->isAnswered());
        static::assertNull($record->session);
    }

    /**
     * A request is answered once: nobody is asked twice about one code, and answering one twice is a
     * programming error rather than a refusal.
     */
    #[Test]
    #[DataProvider('provideSecondAnswers')]
    public function itRefusesToBeAnsweredTwice(string $first, string $second): void
    {
        // Given
        $record = $this->record();
        $snapshot = AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass());
        $answer = function (string $answer, DateTimeImmutable $at) use ($record, $snapshot): void {
            $answer === 'approve' ? $record->approve($this->session, $snapshot, $at) : $record->deny($at);
        };
        $answer($first, $this->issuedAt->modify('+10 seconds'));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('A device authorization request is answered once');

        // When
        $answer($second, $this->issuedAt->modify('+20 seconds'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSecondAnswers(): iterable
    {
        yield 'approved then approved' => ['approve', 'approve'];
        yield 'approved then refused' => ['approve', 'deny'];
        yield 'refused then approved' => ['deny', 'approve'];
        yield 'refused then refused' => ['deny', 'deny'];
    }

    /**
     * An approval binds a session of the tenant of the record and of no other.
     */
    #[Test]
    public function itRefusesAnApprovalBySomebodyOfAnotherTenant(): void
    {
        // Given
        $record = $this->record();
        $elsewhere = Fixtures::session(Fixtures::user(Fixtures::tenant('other', 'https://other.test')));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('approved with a session of its own tenant');

        // When
        $record->approve($elsewhere, AuthenticationSnapshot::ofSession($elsewhere, $elsewhere->authenticationContextClass()), $this->issuedAt);
    }

    /**
     * RFC 8628 §3.5: the first poll is never too soon, and one that respects the interval is not either.
     */
    #[Test]
    public function aPollThatRespectsTheIntervalIsAnswered(): void
    {
        // Given
        $record = $this->record();

        // When
        $first = $record->polledTooSoon($this->issuedAt);
        $second = $record->polledTooSoon($this->issuedAt->modify('+5 seconds'));

        // Then
        static::assertFalse($first);
        static::assertFalse($second);
        static::assertSame(5, $record->interval);
    }

    /**
     * RFC 8628 §3.5: a client that polls sooner than the interval it was given is told to add five seconds,
     * and what the record expects grows with it, so the two stay in step.
     */
    #[Test]
    public function aPollSoonerThanTheIntervalGrowsIt(): void
    {
        // Given
        $record = $this->record();
        $record->polledTooSoon($this->issuedAt);

        // When
        $tooSoon = $record->polledTooSoon($this->issuedAt->modify('+2 seconds'));

        // Then
        static::assertTrue($tooSoon);
        static::assertSame(10, $record->interval);
    }

    /**
     * Every poll is recorded, the refused ones included: asking again does not buy a faster answer.
     */
    #[Test]
    public function aRefusedPollIsStillAPoll(): void
    {
        // Given
        $record = $this->record();
        $record->polledTooSoon($this->issuedAt);
        $record->polledTooSoon($this->issuedAt->modify('+2 seconds'));

        // When
        $again = $record->polledTooSoon($this->issuedAt->modify('+4 seconds'));

        // Then
        static::assertTrue($again, 'two seconds after the refused poll, and the interval is ten now');
        static::assertEquals($this->issuedAt->modify('+4 seconds'), $record->lastPolledAt);
    }

    /**
     * A record answers for itself rather than trusting what it was handed.
     */
    #[Test]
    #[DataProvider('provideRecordsThatDoNotHoldTogether')]
    public function itRefusesWhatItCouldNotHaveWritten(string $deviceCodeHash, string $userCodeHash, string $expiresAt, int $interval, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new DeviceAuthorizationRecord(
            $deviceCodeHash,
            $userCodeHash,
            Uuid::v7(),
            $this->client,
            new Scopes([new Scope('openid')]),
            null,
            Fixtures::context($this->issuedAt),
            $this->issuedAt,
            new DateTimeImmutable($expiresAt),
            $interval,
        );
    }

    /**
     * @return iterable<string, array{string, string, string, int<0, max>, string}>
     */
    public static function provideRecordsThatDoNotHoldTogether(): iterable
    {
        yield 'a device code that is not a digest' => [
            'the-device-code',
            self::digest('BCDFGHJK'),
            '2026-09-26T09:10:00+00:00',
            5,
            'the hex SHA-256 of its device code',
        ];
        yield 'a user code that is not a digest' => [
            self::digest('the-device-code'),
            'BCDFGHJK',
            '2026-09-26T09:10:00+00:00',
            5,
            'the hex SHA-256 of its user code',
        ];
        yield 'expiring when it was asked for' => [
            self::digest('the-device-code'),
            self::digest('BCDFGHJK'),
            '2026-09-26T09:00:00+00:00',
            5,
            'expires after it was asked for',
        ];
        yield 'expiring before it was asked for' => [
            self::digest('the-device-code'),
            self::digest('BCDFGHJK'),
            '2026-09-26T08:00:00+00:00',
            5,
            'expires after it was asked for',
        ];
        yield 'an interval no client could respect' => [
            self::digest('the-device-code'),
            self::digest('BCDFGHJK'),
            '2026-09-26T09:10:00+00:00',
            0,
            'a polling interval of at least one second',
        ];
        yield 'an interval longer than a client is asked to respect' => [
            self::digest('the-device-code'),
            self::digest('BCDFGHJK'),
            '2026-09-26T09:10:00+00:00',
            DeviceAuthorizationRecord::MAX_INTERVAL + 1,
            'a polling interval of at most 30 seconds, a client respecting it (RFC 8628 section 3.5); 31 given',
        ];
    }

    /**
     * RFC 8628 §3.5: a request is made with an interval of a second at least and of the bound at most, both
     * ends included.
     */
    #[Test]
    #[DataProvider('provideIntervalsARequestIsMadeWith')]
    public function itIsMadeWithAnIntervalFromOneSecondToItsBound(int $interval): void
    {
        // When
        $record = $this->record($interval);

        // Then
        static::assertSame($interval, $record->interval);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideIntervalsARequestIsMadeWith(): iterable
    {
        yield 'a second' => [1];
        yield 'the bound' => [DeviceAuthorizationRecord::MAX_INTERVAL];
    }

    private static function digest(string $value): string
    {
        return DrawnSecret::digestOf($value);
    }

    private function record(int $interval = DeviceAuthorizationRecord::DEFAULT_INTERVAL): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord(
            DrawnSecret::digestOf('the-device-code'),
            UserCode::hashOf('BCDFGHJK'),
            Uuid::v7(),
            $this->client,
            new Scopes([new Scope('openid'), new Scope('profile')]),
            null,
            Fixtures::context($this->issuedAt),
            $this->issuedAt,
            $this->issuedAt->modify('+600 seconds'),
            $interval,
        );
    }
}
