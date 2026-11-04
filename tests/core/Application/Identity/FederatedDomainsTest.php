<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Identity\FederatedDomains;
use Beffroi\Core\Bridge\InMemory\InMemoryUpstreamProviders;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0029, spec/saml.md S-60 to S-63
 */
final class FederatedDomainsTest extends TestCase
{
    private const string ACME = 'https://idp.acme.example/saml';

    private const string INITECH = 'https://idp.initech.example/saml';

    private Tenant $tenant;

    private FederatedDomains $federated;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $providers = new InMemoryUpstreamProviders();
        $providers->declare($this->tenant, new UpstreamProvider(self::ACME, [new EmailDomain('acme.example')]));
        $providers->declare($this->tenant, new UpstreamProvider(self::INITECH, [new EmailDomain('initech.example')]));
        $this->federated = new FederatedDomains($providers);
    }

    /**
     * S-61
     */
    #[Test]
    public function aTenantThatDeclaresAnUpstreamProviderFederates(): void
    {
        // When / Then
        static::assertTrue($this->federated->federates($this->tenant));
    }

    /**
     * S-61
     */
    #[Test]
    public function aTenantThatDeclaresNoUpstreamProviderFederatesNothing(): void
    {
        // When / Then
        static::assertFalse($this->federated->federates(Fixtures::tenant('other')));
    }

    /**
     * S-61
     */
    #[Test]
    #[DataProvider('provideIdentifiers')]
    public function anAddressIsFederatedToTheProviderOfItsDomain(string $identifier, ?string $provider): void
    {
        // When / Then
        static::assertSame($provider, $this->federated->providerOf($this->tenant, $identifier)?->name);
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function provideIdentifiers(): iterable
    {
        yield 'of the domain of a provider' => ['alice@acme.example', self::ACME];
        yield 'of the domain of another provider' => ['bob@initech.example', self::INITECH];
        yield 'of a domain nobody federates' => ['carol@umbrella.example', null];
        yield 'a username' => ['alice', null];
    }

    /**
     * S-61, S-44
     */
    #[Test]
    public function anAddressWhoseDomainTheRuleDoesNotReadIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The domain of an address is no name of the DNS of two labels at least.');

        // When
        $this->federated->providerOf($this->tenant, 'alice@localhost');
    }

    /**
     * S-63
     */
    #[Test]
    #[DataProvider('providePersons')]
    public function aLocalCredentialIsAdmittedForAPersonOfNoFederatedDomainOnly(string $username, ?string $email, bool $admitted): void
    {
        // Given
        $user = Fixtures::user($this->tenant, $username);
        if ($email !== null) {
            $user->changeEmail(new EmailAddress($email), false, Fixtures::now());
        }

        // When / Then
        static::assertSame($admitted, $this->federated->admitsLocalCredentials($user));
    }

    /**
     * @return iterable<string, array{string, string|null, bool}>
     */
    public static function providePersons(): iterable
    {
        yield 'a username and no mailbox' => ['alice', null, true];
        yield 'a mailbox of a domain nobody federates' => ['alice', 'alice@umbrella.example', true];
        yield 'a mailbox of a federated domain, not verified' => ['alice', 'alice@acme.example', false];
        yield 'a username of a federated domain' => ['alice@initech.example', null, false];
        yield 'a username of a domain nobody federates' => ['alice@umbrella.example', null, true];
        yield 'a username whose domain the rule does not read' => ['alice@localhost', null, false];
    }

    /**
     * S-63
     */
    #[Test]
    public function aTenantThatFederatesNothingAdmitsEveryLocalCredential(): void
    {
        // Given
        $user = Fixtures::user(Fixtures::tenant('other'), 'alice@localhost');

        // When / Then
        static::assertTrue($this->federated->admitsLocalCredentials($user));
    }
}
