<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function array_map;
use function chr;
use Heidi\Core\Bridge\Random\FixedRandomness;
use Heidi\Oidc\Application\Secret\UserCodeDrawer;
use Heidi\Oidc\Domain\Device\UserCode;
use function str_split;
use function strpos;

/**
 * A drawer of user codes that draws the codes a test wrote, in the order it wrote them (RFC 8628 §6.1): the
 * bytes behind each one are the places of its characters in the alphabet, which the drawer spells back.
 */
final class UserCodes
{
    /**
     * @param list<string> $codes each of them a code of the shape this provider draws
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
