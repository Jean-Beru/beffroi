<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Port\ServedResponseModesInterface;

/**
 * The response modes an integration wired: the default alone, as spike 1 had, the default and the posted
 * form, as the provider wired from spike 4, or the four the provider wires since issue #163, the two deliveries
 * of a signed document beside them. The names are the ones the ways of answering give themselves.
 */
final readonly class ServedModes
{
    public const string QUERY = 'query';

    public const string FORM_POST = 'form_post';

    public const string SIGNED_QUERY = 'query.jwt';

    public const string SIGNED_FORM_POST = 'form_post.jwt';

    public static function queryOnly(): ServedResponseModesInterface
    {
        return WiredModes::of([self::QUERY]);
    }

    public static function queryAndFormPost(): ServedResponseModesInterface
    {
        return WiredModes::of([self::QUERY, self::FORM_POST]);
    }

    /**
     * JARM §2.1: the two deliveries of a signed answer, beside the two unsigned ones, the alias resolving to
     * the one that delivers the way the default mode does.
     */
    public static function signedToo(): ServedResponseModesInterface
    {
        return WiredModes::of(
            [self::QUERY, self::FORM_POST, self::SIGNED_QUERY, self::SIGNED_FORM_POST],
            [self::SIGNED_QUERY, self::SIGNED_FORM_POST],
            self::SIGNED_QUERY,
        );
    }
}
