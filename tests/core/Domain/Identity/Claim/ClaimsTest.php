<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity\Claim;

use Beffroi\Core\Domain\Identity\Claim\Birthdate;
use Beffroi\Core\Domain\Identity\Claim\ClaimField;
use Beffroi\Core\Domain\Identity\Claim\ClaimInterface;
use Beffroi\Core\Domain\Identity\Claim\Locale;
use Beffroi\Core\Domain\Identity\Claim\Nickname;
use Beffroi\Core\Domain\Identity\Claim\PictureUrl;
use Beffroi\Core\Domain\Identity\Claim\ProfileUrl;
use Beffroi\Core\Domain\Identity\Claim\WebsiteUrl;
use Beffroi\Core\Domain\Identity\Claim\Zoneinfo;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Closure;
use function count;
use DateTimeZone;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #479: the three claims whose set is closed on what exists, and what a closed set refuses.
 */
final class ClaimsTest extends TestCase
{
    /**
     * The set a stored value is already read against when a date is shown to that person, so the two agree
     * instead of one guarding the other.
     */
    #[Test]
    public function theTimeZoneIsOneOfTheNamesOfTheZoneinfoDatabase(): void
    {
        // When
        $field = new Zoneinfo()->field();

        // Then
        static::assertCount(count(DateTimeZone::listIdentifiers()), $field->choices);
        static::assertTrue($field->holds('Europe/Paris'));
        static::assertTrue($field->isPicked());
    }

    #[Test]
    public function aTimeZoneNobodyHasIsRefused(): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The value "Europe/Atlantis" is not one this claim may hold.');

        // When
        new Zoneinfo()->describe($user, 'Europe/Atlantis', Fixtures::now());
    }

    #[Test]
    public function aNameOfTheZoneinfoDatabaseIsWritten(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        new Zoneinfo()->describe($user, 'Pacific/Chatham', Fixtures::now());

        // Then
        static::assertSame('Pacific/Chatham', $user->profile->zoneinfo);
    }

    /**
     * A deployment that names no language offers something to type, there being nothing to choose.
     */
    #[Test]
    public function theLanguageOfADeploymentThatNamesNoneIsALineOfText(): void
    {
        // When / Then
        static::assertSame([], new Locale()->field()->choices);
    }

    #[Test]
    public function theLanguageIsOneOfThoseTheIntegrationNames(): void
    {
        // When
        $field = new Locale([
            'fr' => 'français',
            'ja' => '日本語',
        ])->field();

        // Then
        static::assertSame(['fr' => 'français', 'ja' => '日本語'], $field->choices);
        static::assertFalse($field->isPicked());
    }

    #[Test]
    public function aLanguageOutsideThatSetIsRefused(): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Locale(['fr' => 'français'])->describe($user, 'ja', Fixtures::now());
    }

    /**
     * A browser offers a calendar for a date, and the pattern comes with it for one that does not.
     */
    #[Test]
    public function theBirthdateIsADate(): void
    {
        // When
        $field = new Birthdate()->field();

        // Then
        static::assertSame('date', $field->kind);
        static::assertSame('\d{4}(-\d{2}-\d{2})?', $field->pattern);
    }

    /**
     * OIDC Core §5.1 provides for a year alone, which a date input cannot express: the model holds one
     * all the same, a console and an import writing it.
     */
    #[Test]
    public function aYearAloneIsStillABirthdateTheModelHolds(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        new Birthdate()->describe($user, '1815', Fixtures::now());

        // Then
        static::assertSame('1815', $user->profile->birthdate);
    }

    /**
     * What the shape of a value is, where the set is not closed, stays the model's: a birthdate that is
     * not a date is refused by the profile that holds it and not by the field.
     */
    #[Test]
    public function aBirthdateThatIsNotADateIsRefusedByTheProfile(): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('must be "YYYY-MM-DD" or "YYYY"');

        // When
        new Birthdate()->describe($user, 'the first of May', Fixtures::now());
    }

    /**
     * A claim with no closed set refuses nothing of its own.
     */
    #[Test]
    public function aClaimWithNoClosedSetWritesWhateverItIsGiven(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        new Nickname()->describe($user, 'Ada-of-the-notes', Fixtures::now());

        // Then
        static::assertSame('Ada-of-the-notes', $user->profile->nickname);
        static::assertSame([], new Nickname()->field()->choices);
    }

    /**
     * OIDC Core §5.1, issue #626: three claims are named by the specification and held by a field of
     * another name, the class being named after the field it reads. The name the claim answers and the
     * field it writes are paired in one place (`Profile::describedWith()`), so what a person says under
     * the name of the specification is read back from the field that holds it.
     *
     * @param Closure(Profile): ?string $read
     */
    #[Test]
    #[DataProvider('provideClaimsHeldByAFieldOfAnotherName')]
    public function aClaimNamedByTheSpecificationWritesTheFieldThatHoldsIt(ClaimInterface $claim, string $name, Closure $read): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $claim->describe($user, 'https://ada.example/page', Fixtures::now());

        // Then
        static::assertSame($name, $claim->name());
        static::assertSame('https://ada.example/page', $read($user->profile));
    }

    /**
     * @return iterable<string, array{ClaimInterface, string, Closure(Profile): ?string}>
     */
    public static function provideClaimsHeldByAFieldOfAnotherName(): iterable
    {
        yield 'profile' => [new ProfileUrl(), 'profile', static fn (Profile $profile): ?string => $profile->profileUrl];
        yield 'picture' => [new PictureUrl(), 'picture', static fn (Profile $profile): ?string => $profile->pictureUrl];
        yield 'website' => [new WebsiteUrl(), 'website', static fn (Profile $profile): ?string => $profile->websiteUrl];
    }

    /**
     * Whatever a claim says it is, it is a kind a browser understands without a script.
     */
    #[Test]
    public function theKindOfAClaimIsOneABrowserUnderstandsWithoutAScript(): void
    {
        // When / Then
        static::assertContains(new Birthdate()->field()->kind, ClaimField::KINDS);
    }
}
