<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Encoding\Base64Url;
use function intdiv;
use function str_repeat;

/**
 * RFC 7518 §6.3.1.1
 */
final class RsaModuli
{
    /**
     * The first octet of a modulus, by the number of bits its length leaves to that octet: eight when it leaves none.
     */
    private const string FIRST_OCTETS = "\x80\x01\x02\x04\x08\x10\x20\x40";

    /**
     * The "n" of a modulus of exactly that many bits, behind as many zero octets as asked: only its length is real.
     */
    public static function ofBits(int $bits, int $leadingZeroOctets = 0): string
    {
        return Base64Url::encode(str_repeat("\0", $leadingZeroOctets) . self::FIRST_OCTETS[$bits % 8] . str_repeat("\xA5", intdiv($bits - 1, 8)));
    }
}
