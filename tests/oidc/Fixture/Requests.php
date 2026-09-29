<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function array_map;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;

final class Requests
{
    public const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * A request that passed both stages of the parser, for the first redirect URI of the client, with
     * "openid" and whatever else is asked.
     *
     * @param list<string> $scopes
     * @param list<Prompt> $prompts
     * @param list<string> $acrValues
     */
    public static function authorization(
        Client $client,
        array $scopes = ['openid'],
        array $prompts = [],
        ?int $maxAge = null,
        ?string $idTokenHint = null,
        ?string $loginHint = null,
        ?string $state = 'af0ifjsldkj',
        ?string $nonce = 'n-0S6_WzA2Mj',
        ?ClaimsRequest $claims = null,
        array $acrValues = [],
        ?AuthorizationDetails $authorizationDetails = null,
    ): AuthorizationRequest {
        return new AuthorizationRequest(
            $client,
            $client->registration->redirectUris[0],
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            new CodeChallenge(self::CHALLENGE, CodeChallengeMethod::S256),
            $state,
            $nonce,
            $prompts,
            $maxAge,
            $loginHint,
            acrValues: $acrValues,
            idTokenHint: $idTokenHint,
            claims: $claims,
            authorizationDetails: $authorizationDetails,
        );
    }
}
