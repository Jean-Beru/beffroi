<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * Lists of models of authenticator for the tests, in the schema of the list of the community (aaguid.json of
 * github.com/passkeydeveloper/passkey-authenticator-aaguids): an object whose members are AAGUIDs.
 */
final class AuthenticatorLists
{
    /**
     * @param non-empty-array<string, array<string, mixed>> $models by AAGUID
     */
    public static function document(array $models): string
    {
        return json_encode($models, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * A model as the list writes one, with a logo for a light page and one for a dark page.
     *
     * @return array<string, mixed>
     */
    public static function model(string $name, string $light = AuthenticatorImages::SVG_LIGHT, string $dark = AuthenticatorImages::SVG_DARK): array
    {
        return [
            'name' => $name,
            'icon_light' => $light,
            'icon_dark' => $dark,
        ];
    }
}
