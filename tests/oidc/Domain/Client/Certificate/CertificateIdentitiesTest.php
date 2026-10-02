<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Certificate;

use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentities;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §2.1.2: a registration carries exactly one of the five values, and the kind it carries is
 * what the provider compares the certificate against.
 */
final class CertificateIdentitiesTest extends TestCase
{
    #[Test]
    #[DataProvider('provideRegistrations')]
    public function itReadsTheOneValueTheRegistrationCarries(string $name, string $value): void
    {
        // When
        $identity = CertificateIdentities::fromRegistration([
            $name => $value,
        ]);

        // Then
        static::assertInstanceOf(CertificateIdentityInterface::class, $identity);
        static::assertSame($name, $identity->name());
    }

    #[Test]
    public function aRegistrationThatCarriesNoneIsNoIdentity(): void
    {
        // When
        $identity = CertificateIdentities::fromRegistration([]);

        // Then
        static::assertNull($identity);
    }

    /**
     * RFC 8705 §2.1.2 names one expected value; two of them would be two rules for one certificate.
     */
    #[Test]
    public function twoValuesAreRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A client registers exactly one of the values of RFC 8705 section 2.1.2, not tls_client_auth_subject_dn and tls_client_auth_san_dns.');

        // When
        CertificateIdentities::fromRegistration([
            'tls_client_auth_subject_dn' => 'cn=client',
            'tls_client_auth_san_dns' => 'client.example.com',
        ]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRegistrations(): iterable
    {
        yield 'tls_client_auth_subject_dn' => ['tls_client_auth_subject_dn', 'cn=client,o=Beffroi Test'];

        yield 'tls_client_auth_san_dns' => ['tls_client_auth_san_dns', 'client.example.com'];

        yield 'tls_client_auth_san_uri' => ['tls_client_auth_san_uri', 'https://client.example.com/callback'];

        yield 'tls_client_auth_san_ip' => ['tls_client_auth_san_ip', '198.51.100.7'];

        yield 'tls_client_auth_san_email' => ['tls_client_auth_san_email', 'ops@client.example.com'];
    }
}
