<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;

/**
 * The policy of a tenant of the tests, by the mode it names (decision 0009): the object the endpoint reads,
 * where RegistrationPolicies is the port a deployment wires behind it.
 */
final class Policies
{
    public static function controlled(bool $exemptsConfidentialClientsFromPkce = false): ClientRegistrationPolicy
    {
        return new ClientRegistrationPolicy(InitialAccessTokenAuthorization::MODE, $exemptsConfidentialClientsFromPkce);
    }

    public static function open(bool $exemptsConfidentialClientsFromPkce = false): ClientRegistrationPolicy
    {
        return new ClientRegistrationPolicy(OpenRegistrationAuthorization::MODE, $exemptsConfidentialClientsFromPkce);
    }

    /**
     * @param list<StatementIssuer> $issuers the authorities this tenant pins; none is the mode closed
     */
    public static function attested(array $issuers = []): ClientRegistrationPolicy
    {
        return new ClientRegistrationPolicy(
            SoftwareStatementAuthorization::MODE,
            statementIssuers: $issuers,
        );
    }
}
