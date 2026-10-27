<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Exception\InvalidArgumentException;
use function array_keys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

final class ProfileTest extends TestCase
{
    /**
     * OIDC Core §5.1: birthdate is "YYYY-MM-DD", or "YYYY" when only the year is known, "0000" when it is not.
     */
    #[Test]
    #[DataProvider('provideValidBirthdates')]
    public function itAcceptsTheBirthdateFormsOfOidcCore(string $birthdate): void
    {
        // When / Then
        static::assertSame($birthdate, new Profile(birthdate: $birthdate)->birthdate);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidBirthdates(): iterable
    {
        yield 'full date' => ['1990-05-21'];
        yield 'year only' => ['1990'];
        yield 'unknown year' => ['0000'];
        yield 'the 29th of February of a leap year' => ['2024-02-29'];
        yield 'a day whose year is withheld' => ['0000-05-21'];
        yield 'the 29th of February of a year withheld' => ['0000-02-29'];
    }

    /**
     * Issue #471: the language a person says they read replaces that claim and leaves what they said of
     * themselves alone, a profile being held whole by whoever holds it.
     */
    #[Test]
    public function readingItInAnotherLanguageReplacesThatClaimAlone(): void
    {
        // Given
        $profile = new Profile(name: 'Alice Lovelace', givenName: 'Alice', zoneinfo: 'Europe/London', locale: 'en-GB');

        // When
        $read = $profile->readIn('fr');

        // Then
        static::assertSame('fr', $read->locale);
        static::assertSame('Alice Lovelace', $read->name);
        static::assertSame('Alice', $read->givenName);
        static::assertSame('Europe/London', $read->zoneinfo);
    }

    #[Test]
    public function aProfileIsNotReadInNoLanguage(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The language a profile is read in is either absent or non-empty.');

        // When
        Profile::empty()->readIn('');
    }

    #[Test]
    public function anEmptyProfileHasNoBirthdate(): void
    {
        // When / Then
        static::assertNull(Profile::empty()->birthdate);
    }

    #[Test]
    #[DataProvider('provideInvalidBirthdates')]
    public function itRejectsAnotherBirthdateFormat(string $birthdate): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Profile(birthdate: $birthdate);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidBirthdates(): iterable
    {
        yield 'day first' => ['21/05/1990'];
        yield 'trailing characters' => ['1990-05-21T00:00'];
        yield 'leading characters' => ['born 1990'];
        yield 'leading characters before a date' => ['born 1990-05-21'];
        yield 'a line feed behind a birthdate that would pass' => ["1990-05-21\n"];
        yield 'a line feed behind a year that would pass' => ["1990\n"];
    }

    /**
     * OIDC Core §5.1 and issue #846: a date names a day of the calendar, and its shape alone does not make it
     * one.
     */
    #[Test]
    #[DataProvider('provideDatesThatAreNoDay')]
    public function itRejectsADateThatIsNoDayOfTheCalendar(string $birthdate): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The birthdate "%s" must be a day of the calendar, "YYYY-MM-DD", or a year alone, "YYYY", the year "0000" when it is withheld.',
            $birthdate,
        ));

        // When
        new Profile(birthdate: $birthdate);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDatesThatAreNoDay(): iterable
    {
        yield 'a thirteenth month and a forty-fifth day' => ['2024-13-45'];
        yield 'a month zero' => ['2024-00-10'];
        yield 'a day zero' => ['2024-05-00'];
        yield 'the 31st of a month of thirty days' => ['2024-04-31'];
        yield 'the 29th of February of a common year' => ['2023-02-29'];
        yield 'the 30th of February of a year withheld' => ['0000-02-30'];
    }

    /**
     * The document names no claim and no field: it is the properties of the object, under their own names,
     * so a claim added to the object is a claim the column carries without a line anywhere else.
     *
     * @param array<string, string> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsItAs(Profile $profile, array $document): void
    {
        // When / Then
        static::assertSame($document, $profile->toDocument());
    }

    /**
     * @param array<string, string> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itComesBackOutOfItsDocument(Profile $profile, array $document): void
    {
        // When / Then
        static::assertEquals($profile, Profile::fromDocument($document));
    }

    /**
     * @return iterable<string, array{Profile, array<string, string>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a profile' => [
            new Profile(givenName: 'Alice', familyName: 'Durand', birthdate: '1990-05-21', locale: 'fr-FR'),
            [
                'givenName' => 'Alice',
                'familyName' => 'Durand',
                'birthdate' => '1990-05-21',
                'locale' => 'fr-FR',
            ],
        ];
        yield 'a profile that says nothing' => [Profile::empty(), []];
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotAProfile')]
    public function aDocumentThatIsNotAProfileIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($message);

        // When
        Profile::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotAProfile(): iterable
    {
        yield 'a claim that is not a string' => [
            [
                'nickname' => 12,
            ],
            'A profile is a document of claims named by the fields that hold them, each a string.',
        ];
        yield 'a claim that is a list' => [['Alice'], 'A profile is a document of claims named by the fields that hold them, each a string.'];
        yield 'a name no field holds' => [
            [
                'email' => 'alice@example.com',
            ],
            'Unknown named parameter $email',
        ];
        yield 'a birthdate the object refuses' => [
            [
                'birthdate' => '21/05/1990',
            ],
            'The birthdate "21/05/1990" must be a day of the calendar, "YYYY-MM-DD", or a year alone, "YYYY"',
        ];
    }

    /**
     * The names of OIDC Core §5.1 and not the fields: three of them differ (issue #626).
     */
    #[Test]
    public function itSaysEachClaimUnderItsNameInTheSpecification(): void
    {
        // Given
        $profile = new Profile(givenName: 'Ada', profileUrl: 'https://ada.example/about');

        // When
        $claims = $profile->claims();

        // Then
        static::assertSame('Ada', $claims['given_name']);
        static::assertSame('https://ada.example/about', $claims['profile']);
        static::assertNull($claims['nickname']);
    }

    /**
     * The two directions of one match, held together: a claim written by its name is read back under it.
     */
    #[Test]
    #[DataProvider('provideClaimNames')]
    public function aClaimSaidByItsNameIsReadBackUnderIt(string $claim): void
    {
        // When
        $said = Profile::empty()->describedWith([
            $claim => '2001',
        ]);

        // Then
        static::assertSame('2001', $said->claims()[$claim]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideClaimNames(): iterable
    {
        foreach (array_keys(Profile::empty()->claims()) as $claim) {
            yield $claim => [$claim];
        }
    }

    #[Test]
    public function itSaysThirteenClaims(): void
    {
        // When / Then
        static::assertCount(13, Profile::empty()->claims());
    }
}
