<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The names of this provider a client assertion may name in its "aud" (issue #267): the issuer of the
 * tenant for every client, and the two endpoints CIBA Core §7.1 adds beside it for a client of the
 * backchannel flow.
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
     * FAPI 2.0 Security Profile §5.3.2.1 clause 8: the issuer identifier is the one value an authorization
     * server accepts, although RFC 7523 §3 permits the URL of the token endpoint and OIDC Core §9
     * recommends it.
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
     * CIBA Core §7.1: the provider accepts its issuer identifier, the URL of its token endpoint and the URL
     * of its backchannel authentication endpoint, which is how the specification settles the ambiguity it
     * names over which of them such a client writes.
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

    /**
     * The widening is what the provider serves and not what a client wrote down: a registration naming a
     * grant nothing answers makes no client of that flow, here as at the endpoint where it would start.
     */
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
     * RFC 8705 §5: an endpoint served on a host whose TLS listener asks for a certificate is reached there
     * by a client that presents one, so that URL is a name of it too.
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
