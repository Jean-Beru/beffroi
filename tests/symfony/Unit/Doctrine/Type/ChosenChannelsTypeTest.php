<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctrine\Type;

use App\Doctrine\Type\ChosenChannelsType;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0050
 */
final class ChosenChannelsTypeTest extends TestCase
{
    private const string DOCUMENT = '{"every_kind":["web_push"],"set_apart":{"pending_approval":["mail","sms"]}}';

    #[Test]
    public function aChoiceGoesToTheDatabaseAsItsDocument(): void
    {
        // Given
        $chosen = new ChosenChannels(['web_push'], ['pending_approval' => ['sms', 'mail']]);

        // When
        $written = new ChosenChannelsType()->convertToDatabaseValue($chosen, new SQLitePlatform());

        // Then
        static::assertSame(self::DOCUMENT, $written);
    }

    #[Test]
    public function aChoiceComesBackEqual(): void
    {
        // When
        $read = new ChosenChannelsType()->convertToPHPValue(self::DOCUMENT, new SQLitePlatform());

        // Then
        static::assertEquals(new ChosenChannels(['web_push'], ['pending_approval' => ['mail', 'sms']]), $read);
    }

    #[Test]
    public function aPersonWhoChoseNothingIsANullColumn(): void
    {
        // When / Then
        static::assertNull(new ChosenChannelsType()->convertToDatabaseValue(ChosenChannels::none(), new SQLitePlatform()));
    }

    #[Test]
    public function aNullColumnIsAPersonWhoChoseNothing(): void
    {
        // When
        $read = new ChosenChannelsType()->convertToPHPValue(null, new SQLitePlatform());

        // Then
        static::assertTrue($read->isNone());
    }
}
