<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Fixtures;
use Beffroi\Xml\Tests\Core\Support\Stack;
use function iconv;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, I-5
 */
final class EncodingTricksTest extends TestCase
{
    /**
     * I-5
     */
    #[Test]
    public function aUtf16ResponseWithAByteOrderMarkIsRefused(): void
    {
        // Given
        $bytes = "\xFF\xFE"
        . iconv(
            'UTF-8',
            'UTF-16LE',
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"/>',
        );

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The input starts with a UTF-16 or UTF-32 byte order mark (I-5).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }

    /**
     * I-5
     */
    #[Test]
    public function aDeclaredSingleByteEncodingIsRefused(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/declared-iso-8859-1-refused.xml');

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The declared encoding is not UTF-8 (I-5).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }
}
