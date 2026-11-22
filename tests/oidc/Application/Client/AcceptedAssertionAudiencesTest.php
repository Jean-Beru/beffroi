<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §7.1
 */
final class AcceptedAssertionAudiencesTest extends TestCase
{
    private const string MUTUAL_TLS_ORIGIN = 'https://mtls.id.acme.example';

    private Tenant $tenant;

    private PasswordHash $secretHash;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->secretHash = new FakePasswordHasher()->hash(Clients::SECRET);
    }

    /**
     * FAPI 2.0 Security Profile §5.3.2.1 clause 8
     */
    #[Test]
    public function theIssuerIsTheOneNameAnOrdinaryClientMayName(): void
    {
        // Given
        $client = Clients::confidential($this->tenant, $this->secretHash);

        // When
        $audiences = Methods::acceptedAudiences()->of($this->tenant, $client);

        // Then
        static::assertSame([$this->tenant->issuer->value], $audiences);
    }

    /**
     * CIBA Core §7.1
     */
    #[Test]
    public function aClientOfTheBackchannelFlowMayAlsoNameTheTokenAndBackchannelEndpoints(): void
    {
        // Given
        $client = Clients::backchannel($this->tenant, $this->secretHash);

        // When
        $audiences = Methods::acceptedAudiences(Grants::servedWithCiba())->of($this->tenant, $client);

        // Then
        static::assertSame(
            [
                $this->tenant->issuer->value,
                $this->tenant->issuer->value . '/token',
                $this->tenant->issuer->value . '/backchannel_authentication',
            ],
            $audiences,
        );
    }

    #[Test]
    public function aClientRegisteredForAGrantTheProviderDoesNotServeNamesTheIssuerAlone(): void
    {
        // Given
        $client = Clients::backchannel($this->tenant, $this->secretHash);

        // When
        $audiences = Methods::acceptedAudiences(Grants::served())->of($this->tenant, $client);

        // Then
        static::assertSame([$this->tenant->issuer->value], $audiences);
    }

    /**
     * RFC 8705 §5
     */
    #[Test]
    public function theEndpointsOfTheHostThatAsksForACertificateAreNamesOfThemToo(): void
    {
        // Given
        $client = Clients::backchannel($this->tenant, $this->secretHash);

        // When
        $audiences = Methods::acceptedAudiences(Grants::servedWithCiba(), self::MUTUAL_TLS_ORIGIN)->of($this->tenant, $client);

        // Then
        static::assertSame(
            [
                $this->tenant->issuer->value,
                $this->tenant->issuer->value . '/token',
                $this->tenant->issuer->value . '/backchannel_authentication',
                self::MUTUAL_TLS_ORIGIN . '/token',
                self::MUTUAL_TLS_ORIGIN . '/backchannel_authentication',
            ],
            $audiences,
        );
    }
}
