<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\MutualTlsSection;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * RFC 8705 §2, §5
 */
final class MutualTlsSectionTest extends TestCase
{
    #[Test]
    #[DataProvider('provideOrigins')]
    public function mutualTlsIsOnWhileAHostIsNamed(?string $origin, bool $on): void
    {
        // When / Then
        static::assertSame($on, MutualTlsSection::role($origin)->on);
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function provideOrigins(): iterable
    {
        yield 'none' => [null, false];
        yield 'the empty value of the image' => ['', false];
        yield 'a slash' => ['/', false];
        yield 'a host of its own' => ['https://mtls.op.test', true];
        yield 'the host of the issuer' => ['https://op.test/', true];
    }

    /**
     * RFC 8705 §2.1, §7.4
     */
    #[Test]
    #[DataProvider('provideOriginsAndAuthorities')]
    public function tlsClientAuthIsOnWhileAHostAndAnAuthorityAreNamed(?string $origin, mixed $authorities, bool $on): void
    {
        // When / Then
        static::assertSame($on, MutualTlsSection::authoritiesRole($origin, $authorities)->on);
    }

    /**
     * @return iterable<string, array{?string, mixed, bool}>
     */
    public static function provideOriginsAndAuthorities(): iterable
    {
        yield 'a host and an authority' => ['https://mtls.op.test', [Certificates::AUTHORITY_PEM], true];
        yield 'a host and the empty list of the image' => ['https://mtls.op.test', [], false];
        yield 'an authority and no host' => ['', [Certificates::AUTHORITY_PEM], false];
    }

    /**
     * RFC 8705 §2.1
     */
    #[Test]
    public function theAuthoritiesNamedAreTheOnesTlsClientAuthTrusts(): void
    {
        // When
        $authorities = MutualTlsSection::certificateAuthorities([Certificates::AUTHORITY_PEM]);

        // Then
        static::assertTrue($authorities->issued(Certificates::client(), Fixtures::now()));
    }

    /**
     * RFC 5280 §4.2.1.9
     */
    #[Test]
    public function aNamedCertificateThatIsNoAuthorityIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "mutual_tls.certificate_authorities" is refused: The authority of client certificates "c=FR,o=Beffroi Test,cn=beffroi mtls client" is the certificate of no certificate authority (RFC 5280 §4.2.1.9).');

        // When
        MutualTlsSection::certificateAuthorities([Certificates::pemOf(Certificates::client())]);
    }

    #[Test]
    public function aListThatIsNoListIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIsOrContains('The "beffroi" configuration key "mutual_tls.certificate_authorities" carried by the environment is refused');

        // When
        MutualTlsSection::certificateAuthorities(42);
    }
}
