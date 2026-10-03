<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Archive;

use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: the archive a person asks for of everything this provider holds about them. It is the one
 * file where every sealed column stands in clear at once, which is why it expires on a date fixed when it
 * was asked for and not on one anybody may move.
 */
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

    /**
     * The expiry is counted from the moment it was asked for, so a row always carries the date it goes
     * away on whatever happened to its build.
     */
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

    /**
     * An archive answers the question asked at the moment it was asked, so a second build is not a second
     * document: a retry of the message that builds it finds the row done.
     */
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
    public function anArchiveThatExpiresBeforeItWasAskedForIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An archive expires after it was asked for.');

        // When
        new PersonalArchive(Uuid::v7(), Fixtures::user(), Fixtures::now(), Fixtures::now());
    }

    /**
     * The file name travels in a header that proxies and browsers write down, so it names the archive and
     * never the person.
     */
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

    /**
     * Issue #483: a container names its own extension and the name itself is one rule, so the wrapped file
     * and the plain one are the same name and differ by what the file is.
     */
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
}
