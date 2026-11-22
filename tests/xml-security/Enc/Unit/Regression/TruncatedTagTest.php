<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit\Regression;

use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Enc\Decryptor;
use Beffroi\Xml\Enc\EncryptedData;
use Beffroi\Xml\Enc\Exception\DecryptionFailed;
use Beffroi\Xml\Enc\Exception\MalformedEncryption;
use Beffroi\Xml\Enc\PrivateDecryptionKey;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Enc\Support\Encrypted;
use Beffroi\Xml\Tests\Enc\Support\Fixtures;
use Beffroi\Xml\Tests\Enc\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, CVE-2026-32313, CVE-2026-32600, section 13, E-2, E-3
 */
final class TruncatedTagTest extends TestCase
{
    /**
     * CVE-2026-32313, CVE-2026-32600, §9.2 row 24
     */
    #[Test]
    public function cve202632313AndCve202632600ATruncatedTagFailsInTheOneWay(): void
    {
        // Given
        $document = Loaded::fixture('hostile/tag-truncated-refused.xml');
        $element = Encrypted::dataOf($document);
        $decryptor = new Decryptor(new Loader(Stack::idAttributes()));
        $key = PrivateDecryptionKey::fromPem(Fixtures::bytes('keys/test-signing-key.pem'));

        // Then
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessageIs('The data could not be decrypted (E-3).');

        // When
        $decryptor->decrypt($element, $key);
    }

    /**
     * §9.2 rows 17 and 26, E-2
     */
    #[Test]
    public function theModelRefusesACipherValueWithNoRoomForCiphertext(): void
    {
        // Given
        $document = Loaded::fixture('hostile/data-cipher-value-28-bytes-refused.xml');
        $element = Encrypted::dataOf($document);

        // Then
        $this->expectException(MalformedEncryption::class);
        $this->expectExceptionMessageIs('The cipher value of an EncryptedData holds an IV of 12 bytes, at least one byte of ciphertext and a tag of 16 bytes (E-2).');

        // When
        EncryptedData::of($element);
    }
}
