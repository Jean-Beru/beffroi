<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Heidi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Heidi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Domain\Client\Registration\StatementIssuer;

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
