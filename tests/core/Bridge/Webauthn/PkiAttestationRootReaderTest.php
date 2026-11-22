<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\Webauthn\PkiAttestationRootReader;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\AttestationAuthority;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_replace;

/**
 * RFC 5280 §4.2.1.9
 */
final class PkiAttestationRootReaderTest extends TestCase
{
    #[Test]
    public function theCertificateOfACertificateAuthorityIsARoot(): void
    {
        // Given
        $authority = AttestationAuthority::create();

        // When
        $root = new PkiAttestationRootReader()->read($authority->rootCertificate());

        // Then
        static::assertSame($authority->rootCertificate(), $root->pem);
    }

    #[Test]
    public function theRootIsWrittenTheSameWhateverTheLineEndingsItCameWith(): void
    {
        // Given
        $authority = AttestationAuthority::create();

        // When
        $root = new PkiAttestationRootReader()->read(str_replace("\n", "\r\n", $authority->rootCertificate()) . "\r\n");

        // Then
        static::assertSame($authority->rootCertificate(), $root->pem);
    }

    #[Test]
    public function aCertificateOfNoCertificateAuthorityIsRefused(): void
    {
        // Given
        $leaf = AttestationAuthority::create()->attest()->pem;

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is the certificate of no certificate authority (RFC 5280 §4.2.1.9)');

        // When
        new PkiAttestationRootReader()->read($leaf);
    }

    #[Test]
    public function whatIsNoCertificateIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('A root of passkey attestations is a certificate in PEM');

        // When
        new PkiAttestationRootReader()->read('not a certificate');
    }
}
