<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Archive;

use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Uid\Uuid;

final class PersonalArchiveTest extends TestCase
{
    private const string DOCUMENT = '{"profile":[]}';

    #[Test]
    public function anArchiveJustAskedForHoldsNoDocument(): void
    {
        // When
        $archive = self::asked();

        // Then
        static::assertFalse($archive->isReady());
        static::assertNull($archive->content);
        static::assertNull($archive->builtAt);
    }

    #[Test]
    public function anArchiveExpiresAWeekAfterItWasAskedFor(): void
    {
        // When
        $archive = self::asked();

        // Then
        static::assertSame(
            Fixtures::now()->modify(sprintf('+%d days', PersonalArchive::KEPT_FOR_DAYS))->format('c'),
            $archive->expiresAt->format('c'),
        );
    }

    #[Test]
    public function anArchiveThatHasBeenBuiltHoldsItsDocument(): void
    {
        // Given
        $archive = self::asked();

        // When
        $archive->fill(self::DOCUMENT, Fixtures::now());

        // Then
        static::assertTrue($archive->isReady());
        static::assertSame(self::DOCUMENT, $archive->content);
        static::assertSame(Fixtures::now()->format('c'), $archive->builtAt?->format('c'));
    }

    #[Test]
    public function anArchiveIsBuiltOnce(): void
    {
        // Given
        $archive = self::asked();
        $archive->fill(self::DOCUMENT, Fixtures::now());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An archive is built once.');

        // When
        $archive->fill(self::DOCUMENT, Fixtures::now());
    }

    #[Test]
    public function anArchiveWithNothingInItIsRefused(): void
    {
        // Given
        $archive = self::asked();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An archive holds a document.');

        // When
        $archive->fill('', Fixtures::now());
    }

    #[Test]
    public function anArchiveHasNotExpiredOnTheDayItWasAskedFor(): void
    {
        // When / Then
        static::assertFalse(self::asked()->hasExpired(Fixtures::now()));
    }

    #[Test]
    public function anArchiveHasExpiredOnceItsDateHasCome(): void
    {
        // Given
        $archive = self::asked();

        // When / Then
        static::assertTrue($archive->hasExpired($archive->expiresAt));
    }

    #[Test]
    public function aBuildThatHasNotComeBackInItsDelayHasStalled(): void
    {
        // Given
        $archive = self::asked();

        // When / Then
        static::assertTrue($archive->hasStalled(self::afterTheDelay($archive)));
    }

    #[Test]
    public function aBuildInsideItsDelayHasNotStalled(): void
    {
        // When / Then
        static::assertFalse(self::asked()->hasStalled(Fixtures::now()));
    }

    #[Test]
    public function anArchiveThatHoldsItsDocumentNeverStalls(): void
    {
        // Given
        $archive = self::asked();
        $archive->fill(self::DOCUMENT, Fixtures::now());

        // When / Then
        static::assertFalse($archive->hasStalled(self::afterTheDelay($archive)));
    }

    #[Test]
    public function anArchiveThatExpiresBeforeItWasAskedForIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An archive expires after it was asked for.');

        // When
        new PersonalArchive(Uuid::v7(), Fixtures::user(), Fixtures::now(), Fixtures::now());
    }

    #[Test]
    public function theFileIsNamedAfterTheArchiveAndNeverAfterThePerson(): void
    {
        // Given
        $user = Fixtures::user(username: 'ada-lovelace', subject: 'ada-subject');
        $archive = PersonalArchive::asked(Uuid::v7(), $user, Fixtures::now());

        // When
        $name = $archive->fileName();

        // Then
        static::assertSame(sprintf('archive-%s.json', $archive->id->toRfc4122()), $name);
        static::assertStringNotContainsString('ada-lovelace', $name);
        static::assertStringNotContainsString('ada-subject', $name);
    }

    #[Test]
    public function theFileWrappedInAContainerCarriesTheExtensionOfThatContainer(): void
    {
        // Given
        $archive = self::asked();

        // When
        $name = $archive->fileName('zip');

        // Then
        static::assertSame(sprintf('archive-%s.zip', $archive->id->toRfc4122()), $name);
    }

    private static function asked(): PersonalArchive
    {
        return PersonalArchive::asked(Uuid::v7(), Fixtures::user(), Fixtures::now());
    }

    private static function afterTheDelay(PersonalArchive $archive): DateTimeImmutable
    {
        return $archive->askedAt->modify(sprintf('+%d minutes', PersonalArchive::BUILT_WITHIN_MINUTES));
    }
}
