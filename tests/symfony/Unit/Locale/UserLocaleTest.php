<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Locale;

use App\Locale\ServedLocales;
use App\Locale\UserLocale;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.7, OIDC Core §5.1
 */
final class UserLocaleTest extends TestCase
{
    /**
     * @param list<string> $enabled
     */
    #[Test]
    #[DataProvider('provideClaims')]
    public function theLanguageIsTheClaimWhenThisDeploymentHasItAndTheDefaultOtherwise(
        array $enabled,
        string $default,
        ?string $claimed,
        string $expected,
    ): void {
        // Given
        $locales = new UserLocale(new ServedLocales($enabled, $default));

        // When / Then
        static::assertSame($expected, $locales->of(self::user($claimed)));
    }

    /**
     * @return iterable<string, array{list<string>, string, string|null, string}>
     */
    public static function provideClaims(): iterable
    {
        yield 'the claim, when this deployment serves it' => [['en', 'fr'], 'en', 'fr', 'fr'];
        yield 'the language of a claim whose region this deployment does not serve' => [['en', 'fr'], 'en', 'en-GB', 'en'];
        yield 'the region when this deployment serves it' => [['en', 'fr', 'fr_CA'], 'en', 'fr-CA', 'fr_CA'];
        yield 'the default, for a user who said nothing' => [['en', 'fr'], 'fr', null, 'fr'];
        yield 'the default, for a language this deployment does not have' => [['en', 'fr'], 'en', 'de-DE', 'en'];
        yield 'the default, for a claim that names no language at all' => [['en', 'fr'], 'en', 'not a tag', 'en'];
        yield 'the default, for a claim that is empty' => [['en', 'fr'], 'en', '', 'en'];
    }

    private static function user(?string $locale): User
    {
        $user = Fixtures::user();
        $user->updateProfile(new Profile(locale: $locale), Fixtures::now());

        return $user;
    }
}
