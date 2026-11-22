<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Application\Client\Registration\OpenRegistrationAuthorization;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;

/**
 * Decision 0009
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
     * @param list<StatementIssuer> $issuers none is the mode closed
     */
    public static function attested(array $issuers = []): ClientRegistrationPolicy
    {
        return new ClientRegistrationPolicy(
            SoftwareStatementAuthorization::MODE,
            statementIssuers: $issuers,
        );
    }
}
