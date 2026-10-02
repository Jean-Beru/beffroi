<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;

/**
 * What the tenant of the tests does with a client that registers itself (decision 0009): nothing by
 * default, which is what a deployment that writes nothing gets.
 */
final class RegistrationPolicies
{
    public static function closed(): ClientRegistrationPolicyInterface
    {
        return new ConfigurationClientRegistrationPolicy('acme');
    }

    public static function controlled(bool $exemptsConfidentialClientsFromPkce = false): ClientRegistrationPolicyInterface
    {
        return new ConfigurationClientRegistrationPolicy('acme', InitialAccessTokenAuthorization::MODE, $exemptsConfidentialClientsFromPkce);
    }

    public static function open(bool $exemptsConfidentialClientsFromPkce = false): ClientRegistrationPolicyInterface
    {
        return new ConfigurationClientRegistrationPolicy('acme', OpenRegistrationAuthorization::MODE, $exemptsConfidentialClientsFromPkce);
    }
}
