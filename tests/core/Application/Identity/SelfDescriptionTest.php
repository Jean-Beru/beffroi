<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Identity\SelfDescription;
use Beffroi\Core\Bridge\InMemory\InMemoryClaimHistory;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Event\PersonDescribedThemselves;
use Beffroi\Core\Domain\Identity\Claim\Birthdate;
use Beffroi\Core\Domain\Identity\Claim\Nickname;
use Beffroi\Core\Domain\Identity\Claim\PhoneNumber;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #452: a person says something of themselves, when the tenant lets them. The policy is read here
 * and not by the page, because a page that only hides a field it must not offer is a page whose form can
 * be sent anyway.
 */
final class SelfDescriptionTest extends TestCase
{
    #[Test]
    public function aPersonSaysWhatTheTenantOpens(): void
    {
        // Given
        $user = self::user(['nickname']);

        // When
        self::describing()->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertSame('Ada', $user->profile->nickname);
    }

    #[Test]
    public function anEmptyValueTakesBackWhatTheyHadSaid(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());

        // When
        self::describing()->describe($user, new Nickname(), null, Fixtures::context());

        // Then
        static::assertNull($user->profile->nickname);
    }

    #[Test]
    public function aClaimTheTenantDoesNotOpenIsRefused(): void
    {
        // Given
        $user = self::user(['zoneinfo']);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This tenant does not let a person change "nickname" of themselves.');

        // When
        self::describing()->describe($user, new Nickname(), 'Ada', Fixtures::context());
    }

    #[Test]
    public function aTenantThatOpensNothingRefusesEverything(): void
    {
        // Given
        $user = self::user([]);

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        self::describing()->describe($user, new Nickname(), 'Ada', Fixtures::context());
    }

    /**
     * A value the claim does not hold is refused by the model that holds it, wherever it came from.
     */
    #[Test]
    public function aValueTheClaimDoesNotHoldIsRefused(): void
    {
        // Given
        $user = self::user(['birthdate']);

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        self::describing()->describe($user, new Birthdate(), 'the first of May', Fixtures::context());
    }

    /**
     * Saying a telephone number takes the verification back: what was proved was proved of the number
     * that is gone.
     */
    #[Test]
    public function sayingATelephoneNumberTakesItsVerificationBack(): void
    {
        // Given
        $user = self::user(['phone_number']);
        $user->changePhoneNumber('+44 1865 000000', true, Fixtures::now());

        // When
        self::describing()->describe($user, new PhoneNumber(), '+33 1 23 45 67 89', Fixtures::context());

        // Then
        static::assertSame('+33 1 23 45 67 89', $user->phoneNumber);
        static::assertFalse($user->phoneNumberVerified);
    }

    /**
     * The act is announced and the value is not: the journal writes the act down (issue #454), and what a
     * person said of themselves lives in the row of that person and nowhere else.
     */
    #[Test]
    public function theActIsAnnouncedAndTheValueIsNot(): void
    {
        // Given
        $user = self::user(['nickname']);
        $events = new RecordingEventDispatcher();

        // When
        self::describing($events)->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        $announced = $events->of(PersonDescribedThemselves::class);
        static::assertCount(1, $announced);
        static::assertSame('nickname', $announced[0]->claim);
        static::assertFalse($announced[0]->takenBack);
    }

    /**
     * Issue #482: what the claim used to say and what it says now are written down, in the unit of work
     * that changed the record, because a record changed whose history was not is a hole in the one thing
     * a history is for.
     */
    #[Test]
    public function whatTheClaimUsedToSayIsWrittenDownWithWhatItSaysNow(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), 'Augusta', Fixtures::context());

        // Then
        $changes = $history->lastOf($user, 10);
        static::assertCount(1, $changes);
        static::assertSame('nickname', $changes[0]->claim);
        static::assertSame('Ada', $changes[0]->was);
        static::assertSame('Augusta', $changes[0]->became);
    }

    #[Test]
    public function aClaimFilledInForTheFirstTimeIsAChangeFromNothing(): void
    {
        // Given
        $user = self::user(['nickname']);
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertNull($history->lastOf($user, 10)[0]->was);
    }

    #[Test]
    public function takingAValueBackIsAChangeToNothing(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), null, Fixtures::context());

        // Then
        static::assertNull($history->lastOf($user, 10)[0]->became);
    }

    /**
     * Saying again what a claim already said is an act, which the journal has, and not a change.
     */
    #[Test]
    public function sayingAgainWhatAClaimAlreadySaidIsNoChange(): void
    {
        // Given
        $user = self::user(['nickname']);
        $user->updateProfile(new Profile(nickname: 'Ada'), Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new Nickname(), 'Ada', Fixtures::context());

        // Then
        static::assertSame([], $history->lastOf($user, 10));
    }

    /**
     * Issue #482: the phone number is in it, which is not a claim of the profile and is written its own
     * way, the use case reading every claim through the same interface.
     */
    #[Test]
    public function theTelephoneNumberIsInTheHistoryToo(): void
    {
        // Given
        $user = self::user(['phone_number']);
        $user->changePhoneNumber('+44 1865 000000', true, Fixtures::now());
        $history = new InMemoryClaimHistory();

        // When
        self::describing(history: $history)->describe($user, new PhoneNumber(), '+33 1 23 45 67 89', Fixtures::context());

        // Then
        $changes = $history->lastOf($user, 10);
        static::assertSame('+44 1865 000000', $changes[0]->was);
        static::assertSame('+33 1 23 45 67 89', $changes[0]->became);
    }

    private static function describing(?RecordingEventDispatcher $events = null, ?InMemoryClaimHistory $history = null): SelfDescription
    {
        return new SelfDescription(
            new InMemoryUserRepository(),
            $history ?? new InMemoryClaimHistory(),
            $events ?? new RecordingEventDispatcher(),
            new MockClock(Fixtures::now()),
        );
    }

    /**
     * @param list<string> $opened
     */
    private static function user(array $opened): User
    {
        $tenant = Fixtures::tenant();
        $tenant->adoptSelfServedClaims(new SelfServedClaims($opened));

        return Fixtures::user($tenant);
    }
}
