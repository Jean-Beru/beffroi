<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function deflate_add;
use function deflate_init;
use LogicException;
use function str_repeat;
use const ZLIB_ENCODING_RAW;
use const ZLIB_FINISH;
use const ZLIB_SYNC_FLUSH;

/**
 * §9.2 row 22, RFC 1951
 */
final readonly class DeflateBomb
{
    private const int MEBIBYTE = 1_048_576;

    /**
     * @param positive-int $mebibytes
     */
    public static function inflatingTo(int $mebibytes): string
    {
        $context = deflate_init(ZLIB_ENCODING_RAW, ['level' => 9]);
        if ($context === false) {
            throw new LogicException('zlib could not start a deflation.');
        }
        $zeros = str_repeat("\0", self::MEBIBYTE);
        $first = deflate_add($context, $zeros, ZLIB_SYNC_FLUSH);
        $next = deflate_add($context, $zeros, ZLIB_SYNC_FLUSH);
        $final = deflate_add($context, '', ZLIB_FINISH);
        if ($first === false || $next === false || $final === false) {
            throw new LogicException('zlib could not deflate the bomb.');
        }

        return $first . str_repeat($next, $mebibytes - 1) . $final;
    }
}
