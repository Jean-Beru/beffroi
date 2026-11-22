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
 * Decision 0009, RFC 7591 §1.3
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

        yield 'an environment variable declared empty' => [''];
    }
}
