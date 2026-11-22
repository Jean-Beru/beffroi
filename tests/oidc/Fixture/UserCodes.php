<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function array_map;
use function chr;
use Beffroi\Core\Bridge\Random\FixedRandomness;
use Beffroi\Oidc\Application\Secret\UserCodeDrawer;
use Beffroi\Oidc\Domain\Device\UserCode;
use function str_split;
use function strpos;

/**
 * RFC 8628 §6.1
 */
final class UserCodes
{
    /**
     * @param list<string> $codes
     */
    public static function drawer(array $codes = []): UserCodeDrawer
    {
        return new UserCodeDrawer(new FixedRandomness(array_map(self::bytesOf(...), $codes)));
    }

    private static function bytesOf(string $code): string
    {
        $bytes = '';
        foreach (str_split($code) as $character) {
            $bytes .= chr((int) strpos(UserCode::ALPHABET, $character) & 0xFF);
        }

        return $bytes;
    }
}
