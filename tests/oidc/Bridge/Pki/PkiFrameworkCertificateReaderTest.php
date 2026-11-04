<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\Pki;

use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\UnreadableCertificateException;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 5280 §4.1.2.6, §4.2.1.6
 */
final class PkiFrameworkCertificateReaderTest extends TestCase
{
    private PkiFrameworkCertificateReader $reader;

    protected function setUp(): void
    {
        $this->reader = new PkiFrameworkCertificateReader();
    }

    #[Test]
    public function itReadsTheSubjectDistinguishedName(): void
    {
        // When
        $subject = $this->reader->subjectOf(Certificates::client());

        // Then
        static::assertSame('c=FR,o=Beffroi Test,cn=beffroi mtls client', $subject->distinguishedName);
    }

    /**
     * RFC 8705 §2.1.2
     */
    #[Test]
    public function itReadsEveryKindOfSubjectAlternativeNameRfc8705Names(): void
    {
        // When
        $subject = $this->reader->subjectOf(Certificates::client());

        // Then
        static::assertSame(['client.example.com'], $subject->dnsNames);
        static::assertSame(['https://client.example.com/callback'], $subject->uris);
        static::assertSame(['198.51.100.7'], $subject->ipAddresses);
        static::assertSame(['ops@client.example.com'], $subject->emailAddresses);
    }

    #[Test]
    public function aCertificateWithoutAlternativeNamesCarriesNone(): void
    {
        // When
        $subject = $this->reader->subjectOf(Certificates::other());

        // Then
        static::assertSame(['other.example.com'], $subject->dnsNames);
        static::assertSame([], $subject->uris);
        static::assertSame([], $subject->ipAddresses);
        static::assertSame([], $subject->emailAddresses);
    }

    /**
     * RFC 8705 §2.1.2
     */
    #[Test]
    public function aRegisteredNameIsWrittenTheWayTheOneOfACertificateIs(): void
    {
        // Given
        $registered = 'C=FR,O=Beffroi Test,CN=beffroi mtls client';

        // When
        $written = $this->reader->distinguishedName($registered);

        // Then
        static::assertSame($this->reader->subjectOf(Certificates::client())->distinguishedName, $written);
    }

    #[Test]
    public function bytesThatAreNotACertificateAreRefused(): void
    {
        // Given
        $certificate = ClientCertificate::fromBase64('bm90IGEgY2VydGlmaWNhdGU=') ?? static::fail('The fixture is base64.');

        // Then
        $this->expectException(UnreadableCertificateException::class);
        $this->expectExceptionMessageIs('The certificate presented is not an X.509 certificate.');

        // When
        $this->reader->subjectOf($certificate);
    }

    #[Test]
    public function aValueThatIsNotADistinguishedNameIsRefused(): void
    {
        // Then
        $this->expectException(UnreadableCertificateException::class);
        $this->expectExceptionMessageIs('The value is not a distinguished name of RFC 4514.');

        // When
        $this->reader->distinguishedName('beffroi mtls client');
    }
}
