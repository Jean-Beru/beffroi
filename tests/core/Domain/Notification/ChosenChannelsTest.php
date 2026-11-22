<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Notification;

use Beffroi\Core\Domain\Credential\CredentialChangeKind;
use Beffroi\Core\Domain\Notification\ChoosableNotificationKindInterface;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0050
 */
final class ChosenChannelsTest extends TestCase
{
    #[Test]
    public function aPersonWhoChoseNothingIsReachedByEveryChannel(): void
    {
        // When / Then
        static::assertTrue(ChosenChannels::none()->reaches(self::approval(), 'sms'));
    }

    #[Test]
    #[DataProvider('provideChoicesOfEveryKind')]
    public function theChoiceForEveryKindHoldsForAKindNotSetApart(string $channel, bool $reached): void
    {
        // Given
        $chosen = new ChosenChannels(['web_push', 'mail']);

        // When / Then
        static::assertSame($reached, $chosen->reaches(self::approval(), $channel));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideChoicesOfEveryKind(): iterable
    {
        yield 'a channel chosen' => ['mail', true];
        yield 'a channel left out' => ['sms', false];
    }

    #[Test]
    #[DataProvider('provideChoicesOfAKindSetApart')]
    public function theChoiceOfAKindSetApartHoldsOverTheChoiceForEveryKind(string $channel, bool $reached): void
    {
        // Given
        $chosen = new ChosenChannels(['web_push'], ['pending_approval' => ['sms']]);

        // When / Then
        static::assertSame($reached, $chosen->reaches(self::approval(), $channel));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideChoicesOfAKindSetApart(): iterable
    {
        yield 'a channel of the kind' => ['sms', true];
        yield 'a channel of every kind' => ['web_push', false];
    }

    #[Test]
    public function aKindSetApartWithNoChannelIsToldByNone(): void
    {
        // Given
        $chosen = new ChosenChannels(null, ['pending_approval' => []]);

        // When / Then
        static::assertFalse($chosen->reaches(self::approval(), 'web_push'));
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aKindNoChoiceNarrowsReachesEveryChannelWhateverWasChosen(): void
    {
        // Given
        $chosen = new ChosenChannels([], ['credential_change' => []]);

        // When / Then
        static::assertTrue($chosen->reaches(new CredentialChangeKind(), 'sms'));
    }

    #[Test]
    public function aChannelIsHeldOnceInTheOrderOfTheNames(): void
    {
        // When
        $chosen = new ChosenChannels(['web_push', 'mail', 'web_push'], ['pending_approval' => ['sms', 'mail']]);

        // Then
        static::assertSame([['mail', 'web_push'], ['pending_approval' => ['mail', 'sms']]], [$chosen->forEveryKind, $chosen->setApart]);
    }

    /**
     * @param list<string>                $forEveryKind
     * @param array<string, list<string>> $setApart
     */
    #[Test]
    #[DataProvider('provideWhatIsNotAName')]
    public function whatIsNotANameIsRefused(array $forEveryKind, array $setApart, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new ChosenChannels($forEveryKind, $setApart);
    }

    /**
     * @return iterable<string, array{list<string>, array<string, list<string>>, string}>
     */
    public static function provideWhatIsNotAName(): iterable
    {
        yield 'an unnamed channel' => [[''], [], 'A channel is named by lowercase letters, digits and underscores, not "".'];
        yield 'a channel with a space' => [['web push'], [], 'A channel is named by lowercase letters, digits and underscores, not "web push".'];
        yield 'a channel in capitals' => [['SMS'], [], 'A channel is named by lowercase letters, digits and underscores, not "SMS".'];
        yield 'a kind with a dot' => [[], ['pending.approval' => []], 'A kind is named by lowercase letters, digits and underscores, not "pending.approval".'];
    }

    #[Test]
    public function theHistoryWritesTheChannelsOfEveryKindAndOfEachKindSetApart(): void
    {
        // Given
        $chosen = new ChosenChannels(['web_push', 'mail'], ['pending_approval' => []]);

        // When
        $history = $chosen->history();

        // Then
        static::assertSame(['notification_channels' => 'mail web_push', 'notification_channels.pending_approval' => ''], $history);
    }

    #[Test]
    public function aPersonWhoChoseNothingHasNothingInTheHistory(): void
    {
        // When / Then
        static::assertSame([], ChosenChannels::none()->history());
    }

    #[Test]
    #[DataProvider('provideChoices')]
    public function aChoiceComesBackFromItsDocument(ChosenChannels $chosen): void
    {
        // When
        $read = ChosenChannels::fromDocument($chosen->toDocument());

        // Then
        static::assertEquals($chosen, $read);
    }

    /**
     * @return iterable<string, array{ChosenChannels}>
     */
    public static function provideChoices(): iterable
    {
        yield 'nothing chosen' => [ChosenChannels::none()];
        yield 'no channel for every kind' => [new ChosenChannels([])];
        yield 'channels for every kind' => [new ChosenChannels(['mail', 'web_push'])];
        yield 'a kind set apart' => [new ChosenChannels(null, ['pending_approval' => ['sms']])];
        yield 'both' => [new ChosenChannels(['web_push'], ['pending_approval' => []])];
    }

    #[Test]
    public function aPersonWhoChoseNothingWritesNoDocument(): void
    {
        // When / Then
        static::assertNull(ChosenChannels::none()->toDocument());
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideWhatIsNotTheDocumentOfAChoice')]
    public function whatIsNotTheDocumentOfAChoiceIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        ChosenChannels::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideWhatIsNotTheDocumentOfAChoice(): iterable
    {
        yield 'channels of every kind that are not a list' => [['every_kind' => 'mail'], 'The channels a person chose are a JSON list.'];
        yield 'a channel that is not a string' => [['every_kind' => [12]], 'A channel a person chose is named by a string.'];
        yield 'kinds set apart that are not an object' => [['set_apart' => 'pending_approval'], 'The member "set_apart" must be a JSON object, got string.'];
        yield 'channels of a kind that are not a list' => [
            ['set_apart' => ['pending_approval' => ['first' => 'mail']]],
            'The channels a person chose are a JSON list.',
        ];
        yield 'a kind that is not a name' => [
            ['set_apart' => ['Pending' => ['mail']]],
            'A kind is named by lowercase letters, digits and underscores, not "Pending".',
        ];
    }

    private static function approval(): ChoosableNotificationKindInterface
    {
        return new class implements ChoosableNotificationKindInterface {
            public function name(): string
            {
                return 'pending_approval';
            }
        };
    }
}
