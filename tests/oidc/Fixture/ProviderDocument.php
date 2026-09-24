<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Heidi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Application\Discovery\DiscoveryHandler;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedAuthenticationContext;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedClaims;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedClientAuthentication;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedDpop;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedGrants;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIdToken;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIntrospection;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIssuerParameter;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedLogout;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTls;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTlsEndpoints;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedPkce;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedPushedAuthorization;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedRequestObjects;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedResponses;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedRevocation;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedSignedAuthorizationResponse;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedUserInfo;
use Heidi\Oidc\Application\Discovery\Metadata\ProviderIdentity;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Token\GrantInterface;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Heidi\Oidc\Port\ServedLogoutChannelsInterface;
use Heidi\Oidc\Port\ServedResponseModesInterface;
use Heidi\Oidc\Port\UnsignedRequestObjectsInterface;

/**
 * The document of a provider, assembled from its capabilities as the wiring of the bundle assembles it,
 * in the order the document publishes them. A test names only the capability it is about and takes the
 * rest as a deployment has them.
 */
final class ProviderDocument
{
    /**
     * @param iterable<GrantInterface>|null $grants
     */
    public static function handler(
        ?EndpointLocatorInterface $endpoints = null,
        ?MutualTlsEndpointLocatorInterface $mutualTlsEndpoints = null,
        ?ClaimsProviderInterface $claims = null,
        ?ProvableMethodsInterface $provable = null,
        ?ServedResponseModesInterface $responseModes = null,
        ?ClientAuthenticationMethodsInterface $methods = null,
        ?PushedAuthorizationRequirementInterface $pushedRequests = null,
        ?UnsignedRequestObjectsInterface $unsignedRequestObjects = null,
        ?ServedLogoutChannelsInterface $logoutChannels = null,
        ?SignatureAlgorithmsInterface $signing = null,
        ?KeyEncryptionAlgorithmsInterface $keyEncryption = null,
        ?ContentEncryptionAlgorithmsInterface $contentEncryption = null,
        ?iterable $grants = null,
        int $maxAge = 3600,
    ): DiscoveryHandler {
        $endpoints ??= new Endpoints();
        $mutualTlsEndpoints ??= $endpoints instanceof MutualTlsEndpointLocatorInterface ? $endpoints : new Endpoints();
        $claims ??= new StandardClaimsProvider();
        $provable ??= Logins::passwordAndPasskey();
        $responseModes ??= ServedModes::queryAndFormPost();
        $methods ??= Methods::all();
        $pushedRequests ??= PushedRequests::requiredOfNobody();
        $unsignedRequestObjects ??= RequestObjectSignings::everyClientSignsThem();
        $logoutChannels ??= ServedChannels::both();
        $signing ??= Algorithms::all();
        $keyEncryption ??= Algorithms::keyEncryption();
        $contentEncryption ??= Algorithms::contentEncryption();
        $grants ??= [new FakeRefreshTokenIssuingGrant(Grants::authorizationCode()), new FakeRefreshTokenSpendingGrant(Grants::refreshToken())];

        $algorithms = new AnnouncedAlgorithms($signing, $keyEncryption, $contentEncryption);
        $grantTypes = new ServedGrants($grants);

        return new DiscoveryHandler([
            new ProviderIdentity($endpoints),
            new AnnouncedScopes($claims, $grantTypes),
            new AnnouncedResponses($responseModes),
            new AnnouncedGrants($grantTypes),
            new AnnouncedAuthenticationContext($provable),
            new AnnouncedIdToken($algorithms),
            new AnnouncedUserInfo($algorithms),
            new AnnouncedClientAuthentication($methods, $algorithms),
            new AnnouncedClaims($claims),
            new AnnouncedRequestObjects($unsignedRequestObjects, $algorithms),
            new AnnouncedPkce(),
            new AnnouncedRevocation($endpoints, $methods, $algorithms),
            new AnnouncedPushedAuthorization($endpoints, $pushedRequests),
            new AnnouncedIntrospection($endpoints, $methods, $algorithms),
            new AnnouncedIssuerParameter(),
            new AnnouncedLogout($endpoints, $logoutChannels),
            new AnnouncedMutualTls($methods),
            new AnnouncedDpop($algorithms),
            new AnnouncedSignedAuthorizationResponse($responseModes, $algorithms),
            new AnnouncedMutualTlsEndpoints($mutualTlsEndpoints),
        ], $maxAge);
    }

    /**
     * @param iterable<GrantInterface>|null $grants
     *
     * @return array<string, mixed>
     */
    public static function of(
        ?EndpointLocatorInterface $endpoints = null,
        ?MutualTlsEndpointLocatorInterface $mutualTlsEndpoints = null,
        ?ClaimsProviderInterface $claims = null,
        ?ProvableMethodsInterface $provable = null,
        ?ServedResponseModesInterface $responseModes = null,
        ?ClientAuthenticationMethodsInterface $methods = null,
        ?PushedAuthorizationRequirementInterface $pushedRequests = null,
        ?UnsignedRequestObjectsInterface $unsignedRequestObjects = null,
        ?ServedLogoutChannelsInterface $logoutChannels = null,
        ?SignatureAlgorithmsInterface $signing = null,
        ?KeyEncryptionAlgorithmsInterface $keyEncryption = null,
        ?ContentEncryptionAlgorithmsInterface $contentEncryption = null,
        ?iterable $grants = null,
        int $maxAge = 3600,
    ): array {
        return self::handler(
            $endpoints,
            $mutualTlsEndpoints,
            $claims,
            $provable,
            $responseModes,
            $methods,
            $pushedRequests,
            $unsignedRequestObjects,
            $logoutChannels,
            $signing,
            $keyEncryption,
            $contentEncryption,
            $grants,
            $maxAge,
        )
            ->handle(Fixtures::tenant())
            ->toArray();
    }
}
