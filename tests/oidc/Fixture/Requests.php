<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function array_map;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scope;

final class Requests
{
    public const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
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
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
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
