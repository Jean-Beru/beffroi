<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\NamespaceRefused;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Tests\Core\Support\Stack;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, I-6
 */
final class RelativeNamespaceUriTest extends TestCase
{
    /**
     * I-6
     */
    #[Test]
    public function aRelativeNamespaceUriIsRefusedAtLoad(): void
    {
        // Given
        $bytes = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><saml:Assertion xmlns:saml="assertion" ID="_a"/></samlp:Response>';

        // Then
        $this->expectException(NamespaceRefused::class);
        $this->expectExceptionMessageIs('A namespace declaration is not an absolute URI (I-6).');

        // When
        new Loader(Stack::idAttributes())->load($bytes);
    }
}
