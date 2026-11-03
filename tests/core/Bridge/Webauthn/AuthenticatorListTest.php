<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\Webauthn\AuthenticatorList;
use Beffroi\Core\Exception\AuthenticatorListRefusedException;
use Beffroi\Core\Tests\Fixture\AuthenticatorImages;
use Beffroi\Core\Tests\Fixture\AuthenticatorLists;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtoupper;
use Symfony\Component\Uid\Uuid;

/**
 * The list of passkey providers the community keeps, read as the schema of its repository writes it
 * (aaguid.json.schema of github.com/passkeydeveloper/passkey-authenticator-aaguids), and refused whole when it
 * is anything else or names nothing.
 */
final class AuthenticatorListTest extends TestCase
{
    private const string AAGUID = '50726f74-6f6e-5061-7373-50726f746f6e';

    #[Test]
    public function theListNamesAModelWithItsLogoForEachTheme(): void
    {
        // Given
        $list = AuthenticatorList::fromJson(AuthenticatorLists::document([self::AAGUID => AuthenticatorLists::model('Proton Pass')]));

        // When
        $model = $list->model(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame('Proton Pass', $model?->name);
        static::assertSame(AuthenticatorList::SOURCE, $model->source);
        static::assertSame([AuthenticatorImages::SVG_LIGHT, AuthenticatorImages::SVG_DARK], [$model->logo?->light, $model->logo?->dark]);
        static::assertNull($model->certification);
    }

    /**
     * @param array<string, string> $icons
     */
    #[Test]
    #[DataProvider('provideSingleIcons')]
    public function theOneIconOfAModelIsItsLogoForBothThemes(array $icons, string $icon): void
    {
        // Given
        $list = AuthenticatorList::fromJson(AuthenticatorLists::document([
            self::AAGUID => [
                'name' => 'Proton Pass',
                ...$icons,
            ],
        ]));

        // When
        $model = $list->model(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame([$icon, $icon], [$model?->logo?->light, $model?->logo?->dark]);
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function provideSingleIcons(): iterable
    {
        yield 'for a light page' => [
            [
                'icon_light' => AuthenticatorImages::SVG_LIGHT,
            ],
            AuthenticatorImages::SVG_LIGHT,
        ];
        yield 'for a dark page' => [
            [
                'icon_dark' => AuthenticatorImages::SVG_DARK,
            ],
            AuthenticatorImages::SVG_DARK,
        ];
    }

    #[Test]
    public function aModelWithoutIconHasNoLogo(): void
    {
        // Given
        $list = AuthenticatorList::fromJson(AuthenticatorLists::document([
            self::AAGUID => [
                'name' => 'Proton Pass',
            ],
        ]));

        // When
        $model = $list->model(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame('Proton Pass', $model?->name);
        static::assertNull($model->logo);
    }

    #[Test]
    public function anAaguidIsFoundWhicheverCaseTheListWritesItIn(): void
    {
        // Given
        $list = AuthenticatorList::fromJson(AuthenticatorLists::document([strtoupper(self::AAGUID) => AuthenticatorLists::model('Proton Pass')]));

        // When / Then
        static::assertSame('Proton Pass', $list->model(Uuid::fromString(self::AAGUID))?->name);
    }

    #[Test]
    public function anAaguidTheListDoesNotNameNamesNothing(): void
    {
        // Given
        $list = AuthenticatorList::fromJson(AuthenticatorLists::document([self::AAGUID => AuthenticatorLists::model('Proton Pass')]));

        // When / Then
        static::assertNull($list->model(Uuid::v4()));
    }

    #[Test]
    public function theListCountsTheModelsItNames(): void
    {
        // Given
        $list = AuthenticatorList::fromJson(AuthenticatorLists::document([
            self::AAGUID => AuthenticatorLists::model('Proton Pass'),
            'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => AuthenticatorLists::model('Google Password Manager'),
        ]));

        // When / Then
        static::assertSame(2, $list->count());
    }

    /**
     * The schema leaves a model open to members it does not define: one is left aside, not refused.
     */
    #[Test]
    public function aMemberTheSchemaDoesNotDefineIsLeftAside(): void
    {
        // Given
        $document = AuthenticatorLists::document([
            self::AAGUID => [
                ...AuthenticatorLists::model('Proton Pass'),
                'vendor' => [
                    'url' => 'https://proton.me',
                ],
            ],
        ]);

        // When
        $list = AuthenticatorList::fromJson($document);

        // Then
        static::assertSame('Proton Pass', $list->model(Uuid::fromString(self::AAGUID))?->name);
    }

    #[Test]
    #[DataProvider('provideDocumentsThatAreNotTheList')]
    public function aDocumentThatIsNotTheListIsRefused(string $document, string $reason): void
    {
        // Then
        $this->expectException(AuthenticatorListRefusedException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        AuthenticatorList::fromJson($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDocumentsThatAreNotTheList(): iterable
    {
        $aaguid = self::AAGUID;
        $png = AuthenticatorImages::PNG;

        yield 'not JSON' => ['<html></html>', 'it is not JSON'];
        yield 'a list' => ['[{"name": "Proton Pass"}]', 'it is not a JSON object'];
        yield 'a string' => ['"Proton Pass"', 'it is not a JSON object'];
        yield 'an empty object, which is what a retired list becomes' => ['{}', 'it names no authenticator, which is what a retired list becomes'];
        yield 'a member that is not an AAGUID' => ['{"proton-pass": {"name": "Proton Pass"}}', '"proton-pass" is not an AAGUID'];
        yield 'a model that is not an object' => ["{\"{$aaguid}\": \"Proton Pass\"}", "what it says of {$aaguid} is not an object"];
        yield 'a model without a name' => ["{\"{$aaguid}\": {\"icon_light\": \"{$png}\"}}", "{$aaguid} has no name"];
        yield 'a model with an empty name' => ["{\"{$aaguid}\": {\"name\": \"\"}}", "{$aaguid} has no name"];
        yield 'a model whose name is not a string' => ["{\"{$aaguid}\": {\"name\": 7}}", "{$aaguid} has no name"];
        yield 'an icon that is not a string' => [
            "{\"{$aaguid}\": {\"name\": \"Proton Pass\", \"icon_dark\": null}}",
            "the \"icon_dark\" of {$aaguid} is not a data: URL",
        ];
        yield 'an icon of the web' => [
            "{\"{$aaguid}\": {\"name\": \"Proton Pass\", \"icon_light\": \"https://proton.me/logo.svg\"}}",
            "the logo of {$aaguid} is refused: The logo of an authenticator is a PNG or an SVG image in a base64 data: URL (RFC 2397).",
        ];
    }
}
