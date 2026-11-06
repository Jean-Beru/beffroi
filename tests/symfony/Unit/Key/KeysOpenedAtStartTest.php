<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Key;

use App\Key\KeysOpenedAtStart;
use App\Tests\Symfony\Fixture\AmbientTenant;
use App\Tests\Symfony\Fixture\RecordedMessages;
use App\Tests\Symfony\Fixture\RecordingKeys;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use Throwable;

/**
 * Decision 0018
 */
final class KeysOpenedAtStartTest extends TestCase
{
    #[Test]
    public function eachFamilyIsOpenedForTheAmbientTenant(): void
    {
        // Given
        $signing = new RecordingKeys();
        $data = new RecordingKeys();

        // When
        self::opening([$signing, $data])->open();

        // Then
        static::assertSame([['acme'], ['acme']], [$signing->openedFor, $data->openedFor]);
    }

    #[Test]
    #[DataProvider('provideWhatStopsTheOpening')]
    public function whatStopsTheOpeningIsAnErrorAndNoFailureOfTheStart(Throwable $refusal, string $logged): void
    {
        // Given
        $logs = new RecordedMessages();

        // When
        self::opening([new RecordingKeys($refusal)], $logs)->open();

        // Then
        static::assertSame([$logged], $logs->at(LogLevel::ERROR));
    }

    /**
     * @return iterable<string, array{Throwable, string}>
     */
    public static function provideWhatStopsTheOpening(): iterable
    {
        yield 'an outage of the KMS' => [
            new KmsUnavailableException('Failed to reach the KMS.'),
            'The KMS did not answer while the keys were opened at start: each one is opened at its first use.',
        ];
        yield 'a key refused' => [
            new RuntimeException('The envelope was not sealed for this tenant.'),
            'The keys could not be opened at start: each one is opened at its first use.',
        ];
    }

    #[Test]
    public function theFamiliesAfterAnOutageAreLeftToTheirFirstUse(): void
    {
        // Given
        $data = new RecordingKeys();

        // When
        self::opening([new RecordingKeys(new KmsUnavailableException('Failed to reach the KMS.')), $data])->open();

        // Then
        static::assertSame([], $data->openedFor);
    }

    /**
     * @param list<RecordingKeys> $keys
     */
    private static function opening(array $keys, RecordedMessages $logs = new RecordedMessages()): KeysOpenedAtStart
    {
        return new KeysOpenedAtStart(new AmbientTenant(Fixtures::tenant()), $keys, $logs);
    }
}
