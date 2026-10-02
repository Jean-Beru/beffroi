<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Bridge\Configuration;

use DateInterval;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0009: what a deployment wrote about the clients that register themselves is the policy of the
 * one tenant it declares. A mode is named per tenant and nothing opens it for more than the tenant that
 * names it, which is what keeps the mode that registers strangers (RFC 7591 §1.3) where it was written.
 */
final class ConfigurationClientRegistrationPolicyTest extends TestCase
{
    #[Test]
    public function theModeADeploymentNamedIsThePolicyOfItsTenant(): void
    {
        // Given
        $policies = new ConfigurationClientRegistrationPolicy(
            'acme',
            OpenRegistrationAuthorization::MODE,
            true,
            new DateInterval('PT86400S'),
            new DateInterval('PT3600S'),
        );

        // When
        $policy = $policies->policyFor(Fixtures::tenant());

        // Then
        static::assertNotNull($policy);
        static::assertSame(OpenRegistrationAuthorization::MODE, $policy->mode);
        static::assertTrue($policy->exemptsConfidentialClientsFromPkce);
        static::assertSame(86400, $policy->keepsAClientUnusedFor->s);
        static::assertSame(3600, $policy->keepsAClientNeverUsedFor->s);
    }

    /**
     * A tenant this deployment says nothing about is a tenant that registers nobody, whatever the tenant
     * it does declare is open to.
     */
    #[Test]
    public function aTenantThisDeploymentSaysNothingAboutRegistersNobody(): void
    {
        // Given
        $policies = new ConfigurationClientRegistrationPolicy('acme', OpenRegistrationAuthorization::MODE);

        // When
        $policy = $policies->policyFor(Fixtures::tenant('another'));

        // Then
        static::assertNull($policy);
    }

    /**
     * Closed is the default and closed is the absence of a policy: a deployment that named no mode has
     * none, and an empty name is no name, which is what an environment variable nobody set gives.
     */
    #[Test]
    #[DataProvider('provideNamesThatAreNoMode')]
    public function aDeploymentThatNamedNoModeRegistersNobody(?string $mode): void
    {
        // Given
        $policies = new ConfigurationClientRegistrationPolicy('acme', $mode);

        // When
        $policy = $policies->policyFor(Fixtures::tenant());

        // Then
        static::assertNull($policy);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideNamesThatAreNoMode(): iterable
    {
        yield 'a deployment that wrote nothing' => [null];

        yield 'an environment variable nobody set' => [''];
    }
}
