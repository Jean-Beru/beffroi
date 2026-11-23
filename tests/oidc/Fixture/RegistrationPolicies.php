<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationClientRegistrationPolicy;

/**
 * Decision 0009
 */
final class RegistrationPolicies
{
    public static function closed(): ConfigurationClientRegistrationPolicy
    {
        return new ConfigurationClientRegistrationPolicy('acme');
    }

    public static function controlled(bool $exemptsConfidentialClientsFromPkce = false): ConfigurationClientRegistrationPolicy
    {
        return new ConfigurationClientRegistrationPolicy('acme', InitialAccessTokenAuthorization::MODE, $exemptsConfidentialClientsFromPkce);
    }

    public static function open(bool $exemptsConfidentialClientsFromPkce = false): ConfigurationClientRegistrationPolicy
    {
        return new ConfigurationClientRegistrationPolicy('acme', OpenRegistrationAuthorization::MODE, $exemptsConfidentialClientsFromPkce);
    }
}
