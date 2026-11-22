<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use Beffroi\Xml\Dsig\PrivateKey;
use function file_get_contents;
use function is_string;
use LogicException;
use function preg_replace;
use function sprintf;

/**
 * Section 9.1
 */
final readonly class TestKeys
{
    /**
     * @param 'idp'|'sp' $key
     */
    public static function signingKey(string $key): PrivateKey
    {
        return PrivateKey::fromPem(self::bytes($key . '-signing-key.pem'));
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public static function certificate(string $key): string
    {
        $certificate = preg_replace('~-----[A-Z ]+-----|\s+~', '', self::bytes($key . '-signing-certificate.pem'));
        if (! is_string($certificate)) {
            throw new LogicException('The certificate of a test key cannot be read.');
        }

        return $certificate;
    }

    private static function bytes(string $file): string
    {
        $bytes = file_get_contents(__DIR__ . '/../Fixture/keys/' . $file);
        if (! is_string($bytes)) {
            throw new LogicException(sprintf('The test key file %s cannot be read.', $file));
        }

        return $bytes;
    }
}
