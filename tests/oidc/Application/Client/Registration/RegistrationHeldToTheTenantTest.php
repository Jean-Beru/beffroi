<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Client\Registration\RegistrationHeldToTheTenant;
use Beffroi\Oidc\Application\Scope\OfferedScopes;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0009: a client that registers itself gets nothing a declared client does not get. What the
 * wiring does not already say is what the tenant hands out tokens for, which is what its document
 * announces (issues #278 and #920).
 */
final class RegistrationHeldToTheTenantTest extends TestCase
{
    #[Test]
    public function aScopeTheTenantOffersHolds(): void
    {
        // Given
        $metadata = Registrations::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'scope' => 'openid profile',
        ]);
        $registration = Registrations::reader()->read('drawn-identifier', $metadata, true);

        // When
        $this->offer()->assertHolds(Fixtures::tenant(), $registration, $metadata);

        // Then
        static::assertSame(['openid', 'profile'], $registration->allowedScopes->values());
    }

    /**
     * Issue #920: the scope of an API the deployment declares for the tenant is one the tenant hands out
     * tokens for, so a client that registers itself may register it, where no client of the tenant
     * registered it before.
     */
    #[Test]
    public function aScopeTheDeploymentDeclaresHolds(): void
    {
        // Given
        $metadata = Registrations::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'scope' => 'openid billing.read',
        ]);
        $registration = Registrations::reader()->read('drawn-identifier', $metadata, true);

        // When
        $this->offer(['billing.read'])->assertHolds(Fixtures::tenant(), $registration, $metadata);

        // Then
        static::assertSame(['openid', 'billing.read'], $registration->allowedScopes->values());
    }

    /**
     * A scope no claims provider serves, the deployment does not declare and no client of the tenant
     * registered does not exist for that tenant: a client that registers itself cannot write it into the
     * document by asking for it.
     */
    #[Test]
    public function aScopeTheTenantDoesNotHandOutTokensForIsRefused(): void
    {
        // Given
        $metadata = Registrations::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'scope' => 'openid billing.read',
        ]);
        $registration = Registrations::reader()->read('drawn-identifier', $metadata, true);

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIs('The client "drawn-identifier" registers the scope "billing.read", which this tenant does not hand out tokens for (decision 0009).');

        // When
        $this->offer()->assertHolds(Fixtures::tenant(), $registration, $metadata);
    }

    /**
     * The refusal names the member and where it came from, as every refusal of a registration does.
     */
    #[Test]
    public function theRefusalNamesTheMemberAndItsSource(): void
    {
        // Given
        $metadata = Registrations::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'scope' => 'openid billing.read',
        ]);
        $registration = Registrations::reader()->read('drawn-identifier', $metadata, true);

        // When
        try {
            $this->offer()->assertHolds(Fixtures::tenant(), $registration, $metadata);
            static::fail('The tenant hands out no token for that scope.');
        } catch (InvalidClientMetadataException $exception) {
            // Then
            static::assertSame('invalid_client_metadata', $exception->error);
            static::assertSame('scope', $exception->member);
            static::assertSame('the registration the client sent', $exception->source);
        }
    }

    /**
     * @param list<string> $declared what the deployment declares for the tenant of the fixtures
     */
    private function offer(array $declared = []): RegistrationHeldToTheTenant
    {
        return new RegistrationHeldToTheTenant(new OfferedScopes(
            new StandardClaimsProvider(),
            Grants::served(),
            new RegisteredClients([new InMemoryClientRepository()]),
            new ConfigurationDeclaredScopes(Fixtures::tenant()->slug, $declared),
        ));
    }
}
