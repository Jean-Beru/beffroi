<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

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
