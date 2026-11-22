<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Certificate;

use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateSubject;
use Beffroi\Oidc\Domain\Client\Certificate\DnsName;
use Beffroi\Oidc\Domain\Client\Certificate\EmailAddressName;
use Beffroi\Oidc\Domain\Client\Certificate\IpAddressName;
use Beffroi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Beffroi\Oidc\Domain\Client\Certificate\UriName;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §2.1.2
 */
final class CertificateIdentityTest extends TestCase
{
    #[Test]
    #[DataProvider('provideRegisteredNames')]
    public function itRecognisesTheCertificateThatCarriesTheRegisteredName(CertificateIdentityInterface $identity): void
    {
        // When / Then
        static::assertTrue($identity->matches(self::subject()));
    }

    #[Test]
    #[DataProvider('provideNamesOfSomebodyElse')]
    public function itRefusesACertificateThatCarriesAnotherName(CertificateIdentityInterface $identity): void
    {
        // When / Then
        static::assertFalse($identity->matches(self::subject()));
    }

    #[Test]
    #[DataProvider('provideRegistrationNames')]
    public function eachKindNamesTheMetadataItIsRegisteredUnder(CertificateIdentityInterface $identity, string $name): void
    {
        // When / Then
        static::assertSame($name, $identity->name());
    }

    /**
     * RFC 4343 §1
     */
    #[Test]
    public function aDomainNameIsComparedWithoutRegardToCase(): void
    {
        // Given
        $identity = new DnsName('Client.Example.COM');

        // When / Then
        static::assertTrue($identity->matches(self::subject()));
    }

    /**
     * RFC 5321 §2.4
     */
    #[Test]
    public function anAddressIsComparedAsItIsWritten(): void
    {
        // Given
        $identity = new EmailAddressName('OPS@client.example.com');

        // When / Then
        static::assertFalse($identity->matches(self::subject()));
    }

    /**
     * RFC 4291 §2.2, RFC 5280 §4.2.1.6
     */
    #[Test]
    public function anAddressIsComparedAsTheOctetsItStandsFor(): void
    {
        // Given
        $identity = new IpAddressName('2001:db8::1');

        // When / Then
        static::assertTrue($identity->matches(new CertificateSubject('cn=client', ipAddresses: ['2001:0db8:0000:0000:0000:0000:0000:0001'])));
    }

    #[Test]
    #[DataProvider('provideEmptyRegistrations')]
    public function anEmptyValueIsNoName(callable $register, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $register();
    }

    #[Test]
    public function aValueThatIsNotAnAddressIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The registered iPAddress "198.51.100.256" is not an IP address (RFC 8705 section 2.1.2).');

        // When
        new IpAddressName('198.51.100.256');
    }

    /**
     * @return iterable<string, array{CertificateIdentityInterface}>
     */
    public static function provideRegisteredNames(): iterable
    {
        yield 'the subject distinguished name' => [new SubjectDistinguishedName('cn=client,o=Beffroi Test')];

        yield 'a dNSName' => [new DnsName('client.example.com')];

        yield 'a uniformResourceIdentifier' => [new UriName('https://client.example.com/callback')];

        yield 'an iPAddress' => [new IpAddressName('198.51.100.7')];

        yield 'an rfc822Name' => [new EmailAddressName('ops@client.example.com')];
    }

    /**
     * @return iterable<string, array{CertificateIdentityInterface}>
     */
    public static function provideNamesOfSomebodyElse(): iterable
    {
        yield 'another distinguished name' => [new SubjectDistinguishedName('cn=other,o=Beffroi Test')];

        yield 'another dNSName' => [new DnsName('other.example.com')];

        yield 'another uniformResourceIdentifier' => [new UriName('https://client.example.com/callback/')];

        yield 'another iPAddress' => [new IpAddressName('198.51.100.8')];

        yield 'another rfc822Name' => [new EmailAddressName('ops@other.example.com')];
    }

    /**
     * @return iterable<string, array{CertificateIdentityInterface, string}>
     */
    public static function provideRegistrationNames(): iterable
    {
        yield 'tls_client_auth_subject_dn' => [new SubjectDistinguishedName('cn=client'), 'tls_client_auth_subject_dn'];

        yield 'tls_client_auth_san_dns' => [new DnsName('client.example.com'), 'tls_client_auth_san_dns'];

        yield 'tls_client_auth_san_uri' => [new UriName('https://client.example.com/callback'), 'tls_client_auth_san_uri'];

        yield 'tls_client_auth_san_ip' => [new IpAddressName('198.51.100.7'), 'tls_client_auth_san_ip'];

        yield 'tls_client_auth_san_email' => [new EmailAddressName('ops@client.example.com'), 'tls_client_auth_san_email'];
    }

    /**
     * @return iterable<string, array{callable(): CertificateIdentityInterface, string}>
     */
    public static function provideEmptyRegistrations(): iterable
    {
        yield 'a distinguished name' => [
            static fn (): CertificateIdentityInterface => new SubjectDistinguishedName(''),
            'A registered subject distinguished name is not empty (RFC 8705 section 2.1.2).',
        ];

        yield 'a dNSName' => [
            static fn (): CertificateIdentityInterface => new DnsName(''),
            'A registered dNSName is not empty (RFC 8705 section 2.1.2).',
        ];

        yield 'a uniformResourceIdentifier' => [
            static fn (): CertificateIdentityInterface => new UriName(''),
            'A registered uniformResourceIdentifier is not empty (RFC 8705 section 2.1.2).',
        ];

        yield 'an rfc822Name' => [
            static fn (): CertificateIdentityInterface => new EmailAddressName(''),
            'A registered rfc822Name is not empty (RFC 8705 section 2.1.2).',
        ];

        yield 'an iPAddress' => [
            static fn (): CertificateIdentityInterface => new IpAddressName(''),
            'The registered iPAddress "" is not an IP address (RFC 8705 section 2.1.2).',
        ];
    }

    /**
     * RFC 8705 §2.1.2
     */
    private static function subject(): CertificateSubject
    {
        return new CertificateSubject(
            'cn=client,o=Beffroi Test',
            ['client.example.com'],
            ['https://client.example.com/callback'],
            ['198.51.100.7'],
            ['ops@client.example.com'],
        );
    }
}
