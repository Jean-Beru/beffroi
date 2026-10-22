<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0029, spec/saml.md S-60: the three places that ask which provider a domain is federated to read it by
 * one rule, so that none of them takes an address for one of no federated domain while another sends it to its
 * provider: the discovery of the login page (FederatedDomains::providerOf()), the first sign-in through the provider
 * (UpstreamProvider::answersFor() of the domain EmailDomain::ofAddress() read, as JustInTimeProvisioning asks it),
 * and the refusal of a local credential (FederatedDomains::admitsLocalCredentials()).
 */
final class OneDomainRuleTest extends TestCase
{
    private const string PROVIDER = 'https://idp.acme.example/saml';

    private const string REFUSED = 'refused';

    private Tenant $tenant;

    private UpstreamProvider $provider;

    private FederatedDomains $federated;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->provider = new UpstreamProvider(self::PROVIDER, [new EmailDomain('acme.example'), new EmailDomain('xn--bcher-kva.example')]);
        $providers = new InMemoryUpstreamProviders();
        $providers->declare($this->tenant, $this->provider);
        $this->federated = new FederatedDomains($providers);
    }

    /**
     * @param string|null $discovered the provider the login page sends the address to, none, or a refusal
     * @param bool $provisioned whether the provider may create the person of that address
     * @param bool $admitted whether a local credential signs a person named by that address in
     */
    #[Test]
    #[DataProvider('provideSpellings')]
    public function theThreePlacesReadTheDomainOfAnAddressAlike(string $address, ?string $discovered, bool $provisioned, bool $admitted): void
    {
        // Given
        $person = Fixtures::user($this->tenant, $address);

        // When
        $readings = [$this->discovered($address), $this->provisioned($address), $this->federated->admitsLocalCredentials($person)];

        // Then
        static::assertSame([$discovered, $provisioned, $admitted], $readings);
    }

    /**
     * @return iterable<string, array{string, string|null, bool, bool}>
     */
    public static function provideSpellings(): iterable
    {
        yield 'its A-label' => ['alice@xn--bcher-kva.example', self::PROVIDER, true, false];
        yield 'a U-label' => ['alice@bücher.example', self::PROVIDER, true, false];
        yield 'a U-label in capitals' => ['alice@BÜCHER.example', self::PROVIDER, true, false];
        yield 'in capitals' => ['alice@ACME.Example', self::PROVIDER, true, false];
        yield 'a subdomain it does not declare' => ['alice@eu.acme.example', null, false, true];
        yield 'a final dot' => ['alice@acme.example.', self::REFUSED, false, false];
    }

    private function discovered(string $address): ?string
    {
        try {
            return $this->federated->providerOf($this->tenant, $address)?->name;
        } catch (InvalidArgumentException) {
            return self::REFUSED;
        }
    }

    private function provisioned(string $address): bool
    {
        try {
            return $this->provider->answersFor(EmailDomain::ofAddress($address));
        } catch (InvalidArgumentException) {
            return false;
        }
    }
}
