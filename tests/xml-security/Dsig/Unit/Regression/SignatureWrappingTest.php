<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Dsig\Unit\Regression;

use Beffroi\Xml\Core\Exception\DuplicateId;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\WrongReference;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use Beffroi\Xml\Tests\Core\Support\Stack;
use Beffroi\Xml\Tests\Dsig\Support\Fixtures;
use Beffroi\Xml\Tests\Dsig\Support\Loaded;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, CVE-2026-63182, Core I-8, D-1, D-2, D-10
 */
final class SignatureWrappingTest extends TestCase
{
    /**
     * CVE-2026-63182
     */
    #[Test]
    public function cve202663182TheWrappedAssertionWithTheSameIdIsRefusedAtLoad(): void
    {
        // Given
        $bytes = Fixtures::bytes('hostile/xsw-assertion-in-extensions-same-id-refused.xml');

        // Then
        $this->expectException(DuplicateId::class);

        // When
        Loaded::document($bytes);
    }

    /**
     * CVE-2026-63182
     */
    #[Test]
    public function cve202663182TheClaimedElementIsNotTheOneTheReferenceNames(): void
    {
        // Given
        $document = Loaded::fixture('hostile/xsw-assertion-in-extensions-new-id-refused.xml');
        $claimed = $document->elementById('_evil-e1f2g3');
        $verifier = new Verifier(new Loader(Stack::idAttributes()));
        $keys = new VerificationKeys([
            VerificationKey::fromCertificatePem(Fixtures::bytes('keys/test-signing-certificate.pem')),
        ]);

        // Then
        $this->expectException(WrongReference::class);
        $this->expectExceptionMessageIs('The reference does not name the claimed element (D-2).');

        // When
        $verifier->verify($claimed, $keys);
    }
}
