<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\DiscoveryHandler;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedAuthenticationContext;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClaims;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClientAuthentication;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedDpop;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedGrants;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIdToken;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIntrospection;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIssuerParameter;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedLogout;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTls;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTlsEndpoints;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedPkce;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedPushedAuthorization;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedRequestObjects;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedResponses;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedRevocation;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClientRegistration;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Beffroi\Oidc\Application\Scope\OfferedScopes;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedSignedAuthorizationResponse;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedUserInfo;
use Beffroi\Oidc\Application\Discovery\Metadata\ProviderIdentity;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\GrantInterface;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Beffroi\Oidc\Port\ProvableMethodsInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Beffroi\Oidc\Port\RegisteredScopesInterface;
use Beffroi\Oidc\Port\ServedLogoutChannelsInterface;
use Beffroi\Oidc\Port\ServedResponseModesInterface;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;

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
        ?RegisteredScopesInterface $registeredScopes = null,
        ?UnsignedRequestObjectsInterface $unsignedRequestObjects = null,
        ?ServedLogoutChannelsInterface $logoutChannels = null,
        ?SignatureAlgorithmsInterface $signing = null,
        ?KeyEncryptionAlgorithmsInterface $keyEncryption = null,
        ?ContentEncryptionAlgorithmsInterface $contentEncryption = null,
        ?iterable $grants = null,
        int $maxAge = 3600,
        ?ClientRegistrationPolicyInterface $registrationPolicy = null,
    ): DiscoveryHandler {
        $endpoints ??= new Endpoints();
        $mutualTlsEndpoints ??= $endpoints instanceof MutualTlsEndpointLocatorInterface ? $endpoints : new Endpoints();
        $claims ??= new StandardClaimsProvider();
        $provable ??= Logins::passwordAndPasskey();
        $responseModes ??= ServedModes::queryAndFormPost();
        $methods ??= Methods::all();
        $pushedRequests ??= PushedRequests::requiredOfNobody();
        $registeredScopes ??= new RegisteredClients([new InMemoryClientRepository()]);
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
            new AnnouncedScopes(new OfferedScopes($claims, $grantTypes, $registeredScopes, new ConfigurationDeclaredScopes(Fixtures::tenant()->slug))),
            new AnnouncedResponses($responseModes),
            new AnnouncedGrants($grantTypes),
            new AnnouncedAuthenticationContext($provable, Subjects::ofAProvider()),
            new AnnouncedIdToken($algorithms),
            new AnnouncedUserInfo($algorithms),
            new AnnouncedClientAuthentication($methods, $algorithms),
            new AnnouncedClaims($claims),
            new AnnouncedRequestObjects($unsignedRequestObjects, $algorithms),
            new AnnouncedPkce(ChallengeMethods::s256()),
            new AnnouncedRevocation($endpoints, $methods, $algorithms),
            new AnnouncedPushedAuthorization($endpoints, $pushedRequests),
            new AnnouncedIntrospection($endpoints, $methods, $algorithms),
            new AnnouncedIssuerParameter(),
            new AnnouncedLogout($endpoints, $logoutChannels),
            new AnnouncedMutualTls($methods),
            new AnnouncedDpop($algorithms),
            new AnnouncedSignedAuthorizationResponse($responseModes, $algorithms),
            new AnnouncedMutualTlsEndpoints($mutualTlsEndpoints, $grantTypes),
            new AnnouncedClientRegistration($endpoints, $registrationPolicy ?? RegistrationPolicies::closed()),
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
        ?RegisteredScopesInterface $registeredScopes = null,
        ?UnsignedRequestObjectsInterface $unsignedRequestObjects = null,
        ?ServedLogoutChannelsInterface $logoutChannels = null,
        ?SignatureAlgorithmsInterface $signing = null,
        ?KeyEncryptionAlgorithmsInterface $keyEncryption = null,
        ?ContentEncryptionAlgorithmsInterface $contentEncryption = null,
        ?iterable $grants = null,
        int $maxAge = 3600,
        ?ClientRegistrationPolicyInterface $registrationPolicy = null,
    ): array {
        return self::handler(
            $endpoints,
            $mutualTlsEndpoints,
            $claims,
            $provable,
            $responseModes,
            $methods,
            $pushedRequests,
            $registeredScopes,
            $unsignedRequestObjects,
            $logoutChannels,
            $signing,
            $keyEncryption,
            $contentEncryption,
            $grants,
            $maxAge,
            $registrationPolicy,
        )
            ->handle(Fixtures::tenant())
            ->toArray();
    }
}
