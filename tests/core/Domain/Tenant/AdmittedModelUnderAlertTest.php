<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Tenant\AdmittedModelUnderAlert;
use Beffroi\Core\Exception\InvalidArgumentException;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decisions 0006 and 0046
 */
final class AdmittedModelUnderAlertTest extends TestCase
{
    /**
     * Proton Pass: "ProtonPassProton", of no variant RFC 9562 defines (WebAuthn Level 3 §6.1).
     */
    private const string AAGUID = '50726f74-6f6e-5061-7373-50726f746f6e';

    #[Test]
    public function aModelIsNamedByAnyAaguid(): void
    {
        // When
        $model = AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31');

        // Then
        static::assertSame(self::AAGUID, $model->aaguid->toRfc4122());
        static::assertSame('2027-03-31', $model->day());
    }

    #[Test]
    #[DataProvider('provideWhatIsNoAaguid')]
    public function whatIsNoAaguidIsRefused(string $aaguid): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is no AAGUID');

        // When
        AdmittedModelUnderAlert::fromStrings($aaguid, '2027-03-31');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoAaguid(): iterable
    {
        yield 'a word' => ['yubikey'];
        yield 'no hyphens' => ['50726f746f6e5061737350726f746f6e'];
        yield 'a missing digit' => ['50726f74-6f6e-5061-7373-50726f746f6'];
    }

    #[Test]
    #[DataProvider('provideWhatIsNoDay')]
    public function whatIsNoDayIsRefused(string $until): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('until a day written as "2027-03-31"');

        // When
        AdmittedModelUnderAlert::fromStrings(self::AAGUID, $until);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoDay(): iterable
    {
        yield 'a day that does not exist' => ['2027-02-30'];
        yield 'a moment' => ['2027-03-31T12:00:00Z'];
        yield 'another order' => ['31/03/2027'];
        yield 'nothing' => [''];
    }

    #[Test]
    #[DataProvider('provideMomentsTheDayCovers')]
    public function theModelIsAdmittedUntilTheEndOfItsDayInUtc(string $now): void
    {
        // Given
        $model = AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31');

        // When / Then
        static::assertTrue($model->admits(Uuid::fromString(self::AAGUID), new DateTimeImmutable($now)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMomentsTheDayCovers(): iterable
    {
        yield 'a day before' => ['2027-03-30T12:00:00+00:00'];
        yield 'its last second' => ['2027-03-31T23:59:59+00:00'];
        yield 'its last second, told in another zone' => ['2027-04-01T01:59:59+02:00'];
    }

    #[Test]
    #[DataProvider('provideMomentsAfterTheDay')]
    public function theModelIsNoLongerAdmittedAfterItsDay(string $now): void
    {
        // Given
        $model = AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31');

        // When / Then
        static::assertFalse($model->admits(Uuid::fromString(self::AAGUID), new DateTimeImmutable($now)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMomentsAfterTheDay(): iterable
    {
        yield 'the next day' => ['2027-04-01T00:00:00+00:00'];
        yield 'the next day, told in another zone' => ['2027-03-31T22:00:00-02:00'];
    }

    #[Test]
    public function anotherModelIsNotAdmitted(): void
    {
        // Given
        $model = AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31');

        // When / Then
        static::assertFalse($model->admits(Uuid::v4(), new DateTimeImmutable('2027-03-01T00:00:00+00:00')));
    }
}
