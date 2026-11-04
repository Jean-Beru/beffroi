<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Port\ServedResponseModesInterface;

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
     * JARM §2.1
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
