<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use Heidi\Core\Bridge\JwtLibrary\Algorithm\A256Gcm;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\EcdhEsA256Kw;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\EdDsa;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Es256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Ps256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\Rs256;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\RsaKeyBits;
use Heidi\Core\Bridge\JwtLibrary\Algorithm\RsaOaep256;
use Heidi\Core\Bridge\JwtLibrary\JoseContentEncryptionAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JoseKeyAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JoseKeyEncryptionAlgorithms;
use Heidi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;

/**
 * The algorithms of the suite, wired as the bundle wires them, RS256 first and the two a client encrypts
 * to beside them. RSA keys are 2048 bits here: generation is what makes a test slow, and 2048 is what
 * RFC 7518 §3.3 asks for.
 */
final class Algorithms
{
    private static ?Rs256 $rs256 = null;

    private static ?Ps256 $ps256 = null;

    private static ?Es256 $es256 = null;

    private static ?EdDsa $edDsa = null;

    private static ?EcdhEsA256Kw $ecdhEsA256Kw = null;

    private static ?RsaOaep256 $rsaOaep256 = null;

    private static ?A256Gcm $a256Gcm = null;

    private static ?JoseSignatureAlgorithms $all = null;

    private static ?JoseKeyEncryptionAlgorithms $keyEncryption = null;

    private static ?JoseContentEncryptionAlgorithms $contentEncryption = null;

    private static ?JoseKeyAlgorithms $everyUse = null;

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

    public static function ecdhEsA256Kw(): EcdhEsA256Kw
    {
        return self::$ecdhEsA256Kw ??= new EcdhEsA256Kw();
    }

    public static function rsaOaep256(): RsaOaep256
    {
        return self::$rsaOaep256 ??= new RsaOaep256(new RsaKeyBits(2048));
    }

    public static function a256Gcm(): A256Gcm
    {
        return self::$a256Gcm ??= new A256Gcm();
    }

    public static function all(): JoseSignatureAlgorithms
    {
        return self::$all ??= new JoseSignatureAlgorithms([self::rs256(), self::ps256(), self::es256(), self::edDsa()]);
    }

    public static function keyEncryption(): JoseKeyEncryptionAlgorithms
    {
        return self::$keyEncryption ??= new JoseKeyEncryptionAlgorithms([self::ecdhEsA256Kw(), self::rsaOaep256()]);
    }

    public static function contentEncryption(): JoseContentEncryptionAlgorithms
    {
        return self::$contentEncryption ??= new JoseContentEncryptionAlgorithms([self::a256Gcm()]);
    }

    /**
     * A deployment nobody encrypts to: the lists the wiring leaves empty.
     */
    public static function noKeyEncryption(): JoseKeyEncryptionAlgorithms
    {
        return new JoseKeyEncryptionAlgorithms([]);
    }

    public static function noContentEncryption(): JoseContentEncryptionAlgorithms
    {
        return new JoseContentEncryptionAlgorithms([]);
    }

    /**
     * Every algorithm a key may be generated for, the two lists read as one.
     */
    public static function everyUse(): JoseKeyAlgorithms
    {
        return self::$everyUse ??= new JoseKeyAlgorithms(self::all(), self::keyEncryption());
    }
}
