<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\Pki;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateAuthorities;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\UnreadableCertificateException;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §2.1, RFC 5280 §6.1
 */
final class PkiFrameworkCertificateAuthoritiesTest extends TestCase
{
    #[Test]
    public function aCertificateTheAuthorityIssuedIsIssued(): void
    {
        // Given
        $authorities = new PkiFrameworkCertificateAuthorities([Certificates::AUTHORITY_PEM]);

        // When / Then
        static::assertTrue($authorities->issued(Certificates::client(), Fixtures::now()));
    }

    /**
     * RFC 8705 §2.1
     */
    #[Test]
    public function aSelfSignedCertificateCarryingTheSameNamesIsNot(): void
    {
        // Given
        $authorities = new PkiFrameworkCertificateAuthorities([Certificates::AUTHORITY_PEM]);

        // When / Then
        static::assertFalse($authorities->issued(Certificates::selfSigned(), Fixtures::now()));
    }

    /**
     * RFC 8705 §7.4
     */
    #[Test]
    public function aCertificateOfAnAuthorityNotNamedIsNot(): void
    {
        // Given
        $authorities = new PkiFrameworkCertificateAuthorities([Certificates::ANOTHER_AUTHORITY_PEM]);

        // When / Then
        static::assertFalse($authorities->issued(Certificates::client(), Fixtures::now()));
    }

    #[Test]
    public function anyOfTheAuthoritiesMayHaveIssuedIt(): void
    {
        // Given
        $authorities = new PkiFrameworkCertificateAuthorities([Certificates::ANOTHER_AUTHORITY_PEM, Certificates::AUTHORITY_PEM]);

        // When / Then
        static::assertTrue($authorities->issued(Certificates::client(), Fixtures::now()));
    }

    #[Test]
    public function noAuthorityIssuedAnything(): void
    {
        // Given
        $authorities = new PkiFrameworkCertificateAuthorities([]);

        // When / Then
        static::assertFalse($authorities->issued(Certificates::client(), Fixtures::now()));
    }

    /**
     * RFC 5280 §6.1.3
     */
    #[Test]
    #[DataProvider('provideMomentsOutsideTheValidity')]
    public function aCertificateOutsideItsValidityPeriodIsNot(string $moment): void
    {
        // Given
        $authorities = new PkiFrameworkCertificateAuthorities([Certificates::AUTHORITY_PEM]);

        // When / Then
        static::assertFalse($authorities->issued(Certificates::client(), new DateTimeImmutable($moment)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMomentsOutsideTheValidity(): iterable
    {
        yield 'before it is valid' => ['2019-12-31T23:59:59+00:00'];

        yield 'after it expired' => ['2126-01-01T00:00:01+00:00'];
    }

    #[Test]
    public function bytesThatAreNotACertificateAreUnreadable(): void
    {
        // Given
        $authorities = new PkiFrameworkCertificateAuthorities([Certificates::AUTHORITY_PEM]);
        $certificate = ClientCertificate::fromBase64('bm90IGEgY2VydGlmaWNhdGU=') ?? static::fail('The fixture is base64.');

        // Then
        $this->expectException(UnreadableCertificateException::class);
        $this->expectExceptionMessageIs('The certificate presented is not an X.509 certificate.');

        // When
        $authorities->issued($certificate, Fixtures::now());
    }

    /**
     * RFC 5280 §4.2.1.9
     */
    #[Test]
    public function anAuthorityThatIsNoCertificateAuthorityIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The authority of client certificates "c=FR,o=Beffroi Test,cn=beffroi mtls client" is the certificate of no certificate authority (RFC 5280 §4.2.1.9).');

        // When
        new PkiFrameworkCertificateAuthorities([Certificates::pemOf(Certificates::client())]);
    }

    #[Test]
    public function anAuthorityThatIsNoCertificateIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('An authority of client certificates is a certificate in PEM');

        // When
        new PkiFrameworkCertificateAuthorities(['not a certificate']);
    }
}
