<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use Heidi\Core\Bridge\JwtLibrary\Algorithm\EdDsa;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Es256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Ps256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Rs256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Heidi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;

/**
 * The algorithms of the suite, wired as the bundle wires them, RS256 first. RSA keys are 2048 bits here:
 * generation is what makes a test slow, and 2048 is what RFC 7518 §3.3 asks for.
 */
final class Algorithms
{
    private static ?Rs256 $rs256 = null;

    private static ?Ps256 $ps256 = null;

    private static ?Es256 $es256 = null;

    private static ?EdDsa $edDsa = null;

    private static ?JoseSignatureAlgorithms $all = null;

    public static function rs256(): Rs256
    {
        return self::$rs256 ??= new Rs256(new RsaKeyBits(2048));
    }

    public static function ps256(): Ps256
    {
        return self::$ps256 ??= new Ps256(new RsaKeyBits(2048));
    }

    public static function es256(): Es256
    {
        return self::$es256 ??= new Es256();
    }

    public static function edDsa(): EdDsa
    {
        return self::$edDsa ??= new EdDsa();
    }

    public static function all(): JoseSignatureAlgorithms
    {
        return self::$all ??= new JoseSignatureAlgorithms([self::rs256(), self::ps256(), self::es256(), self::edDsa()]);
    }
}
