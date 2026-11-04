<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function array_map;
use Beffroi\Saml2\Bindings\PostForm;
use function implode;
use function parse_str;
use function urlencode;

/**
 * Sections 6.7, 6.8, 9.1, URL Standard §5
 */
final readonly class BrowserForm
{
    /**
     * @param list<array{string, string}> $fields
     */
    public static function body(array $fields): string
    {
        return implode('&', array_map(
            static fn (array $field): string => urlencode($field[0]) . '=' . urlencode($field[1]),
            $fields,
        ));
    }

    /**
     * Section 6.8
     *
     * @return array<array-key, mixed>
     */
    public static function parsed(string $body): array
    {
        parse_str($body, $fields);

        return $fields;
    }

    /**
     * @param list<array{string, string}> $fields
     *
     * @return array<array-key, mixed>
     */
    public static function posted(array $fields): array
    {
        return self::parsed(self::body($fields));
    }

    /**
     * Section 6.7
     *
     * @return array<array-key, mixed>
     */
    public static function submitted(PostForm $form): array
    {
        $fields = [];
        foreach ($form->fields as $name => $value) {
            $fields[] = [$name, $value];
        }

        return self::posted($fields);
    }
}
