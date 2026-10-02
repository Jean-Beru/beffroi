<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Bundle\Tests\Functional\ResponseMode\InventedResponseModeRenderer;
use Beffroi\Oidc\Tests\Fixture\InventedClaimsProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC Discovery §4 and architecture §4.8, §5.2: the provider metadata at the well-known location, the
 * endpoints announced under the issuer whatever host the request came in with.
 */
final class DiscoveryControllerTest extends BrowserTestCase
{
    #[Test]
    public function theMetadataIsServedAsJsonAtTheWellKnownLocation(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        $metadata = self::json($response);
        static::assertSame('https://op.test', $metadata['issuer']);
        static::assertSame('https://op.test/authorize', $metadata['authorization_endpoint']);
        static::assertSame('https://op.test/token', $metadata['token_endpoint']);
        static::assertSame('https://op.test/userinfo', $metadata['userinfo_endpoint']);
        static::assertSame('https://op.test/jwks', $metadata['jwks_uri']);
        static::assertSame('https://op.test/logout', $metadata['end_session_endpoint']);
        static::assertSame('https://op.test/introspect', $metadata['introspection_endpoint']);
        static::assertSame('https://op.test/revoke', $metadata['revocation_endpoint']);
    }

    /**
     * RFC 8414 §3: the second well-known location, where a resource server looks for the metadata of its
     * authorization server; the issuer of this kernel is an origin, so the path is appended to it.
     */
    #[Test]
    public function theSameMetadataIsServedAtTheAuthorizationServerLocation(): void
    {
        // Given
        $this->browser->request('GET', '/.well-known/openid-configuration');
        $openIdConfiguration = self::json($this->browser->getResponse());

        // When
        $this->browser->request('GET', '/.well-known/oauth-authorization-server');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertSame($openIdConfiguration, self::json($response));
    }

    #[Test]
    public function theMetadataIsPubliclyCacheableForOneHour(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $response = $this->browser->getResponse();
        static::assertTrue($response->headers->hasCacheControlDirective('public'));
        static::assertSame('3600', $response->headers->getCacheControlDirective('max-age'));
    }

    /**
     * Decision 0006 and RFC 9207 §3: S256 only, and iss in every authorization response.
     */
    #[Test]
    public function theMetadataAnnouncesWhatTheProviderDoes(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
        static::assertTrue($metadata['authorization_response_iss_parameter_supported']);
    }

    /**
     * OIDC Discovery §3 "scopes_supported", issue #278: "openid" first, then what the wired claims
     * providers serve, the four of OIDC Core §5.4 and the scope this kernel wires a provider of its own
     * for, then the scopes the clients of the tenant registered, which is where a scope that stands for
     * no claim comes from, and "offline_access" last because the wired grants make it good (§11). None of
     * it is enumerated anywhere: a scope is announced because a class serves it or because a client
     * registered it.
     */
    #[Test]
    public function theMetadataAnnouncesTheScopesTheWiringAndTheClientsOfTheTenantHold(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame(
            [
                'openid',
                'profile',
                'email',
                'address',
                'phone',
                InventedClaimsProvider::SCOPE,
                'invoices.read',
                'invoices.write',
                'offline_access',
            ],
            $metadata['scopes_supported'],
        );
    }

    /**
     * OIDC Discovery §3 "claims_supported", issue #278: what the wired claims providers hold together,
     * the claim this kernel wires a provider of its own for included.
     */
    #[Test]
    public function theMetadataAnnouncesTheClaimsTheWiredProvidersServe(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $claims = self::json($this->browser->getResponse())['claims_supported'];
        static::assertIsArray($claims);
        static::assertContains(InventedClaimsProvider::CLAIM, $claims);
    }

    /**
     * RFC 8705 §3.3 and §5: the provider binds access tokens to certificates because the two mutual-TLS
     * methods are wired, and it says where a client presenting one reaches the endpoints, on the host
     * the deployment configured (architecture §5.2).
     */
    #[Test]
    public function theMetadataAnnouncesWhereAClientPresentingACertificateGoes(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertTrue($metadata['tls_client_certificate_bound_access_tokens']);
        static::assertSame(
            [
                'token_endpoint' => 'https://mtls.op.test/token',
                'userinfo_endpoint' => 'https://mtls.op.test/userinfo',
                'introspection_endpoint' => 'https://mtls.op.test/introspect',
                'revocation_endpoint' => 'https://mtls.op.test/revoke',
                'pushed_authorization_request_endpoint' => 'https://mtls.op.test/par',
                'device_authorization_endpoint' => 'https://mtls.op.test/device_authorization',
            ],
            $metadata['mtls_endpoint_aliases'],
        );
    }

    /**
     * OIDC Discovery §3 "response_modes_supported", issue #98: the ways of answering wired into the
     * authorization endpoint, in the order they are wired, plus the "jwt" a signed one makes meaningful
     * (JARM §2.1). Four come from the bundle, the default one, the posted form (Form Post Response Mode §2)
     * and the two deliveries of a signed document; the fifth is the one this kernel wires itself, which is
     * what issue #240 is about: the document announces what is wired and nothing kept beside it. The
     * response types stay "code" alone, in every mode (decision 0006).
     */
    #[Test]
    public function theMetadataAnnouncesTheResponseModesTheIntegrationWires(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame(
            ['query', 'form_post', 'query.jwt', 'form_post.jwt', InventedResponseModeRenderer::MODE, 'jwt'],
            $metadata['response_modes_supported'],
        );
        static::assertSame(['code'], $metadata['response_types_supported']);
    }

    /**
     * JARM §3: a deployment that wires a signed mode says what it signs such an answer with, which is
     * what it signs every other JWS with (issue #98).
     */
    #[Test]
    public function theMetadataAnnouncesWhatASignedAnswerIsSignedWith(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame($metadata['id_token_signing_alg_values_supported'], $metadata['authorization_signing_alg_values_supported']);
    }

    /**
     * OIDC Discovery §3 and RFC 9101 §10.5: both ways a request object comes in are served, a
     * "request_uri" is read back only from a URL its client registered, and "none" is announced beside
     * the wired algorithms because a client of this tenant registered it (issue #98).
     */
    #[Test]
    public function theMetadataAnnouncesHowARequestObjectIsReadAndSignedFor(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertTrue($metadata['request_parameter_supported']);
        static::assertTrue($metadata['request_uri_parameter_supported']);
        static::assertTrue($metadata['require_request_uri_registration']);
        static::assertSame(['RS256', 'PS256', 'ES256', 'EdDSA', 'none'], $metadata['request_object_signing_alg_values_supported']);
    }

    /**
     * OIDC Discovery §3 "acr_values_supported", decision 0010: the classes of the policy of the tenant the
     * logins of the firewall, a password and a passkey, can prove: the four of the default policy.
     */
    #[Test]
    public function theMetadataAnnouncesTheClassesThePasswordAndThePasskeyProve(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame(['phrh', 'phr', '2', '1'], self::json($this->browser->getResponse())['acr_values_supported']);
    }

    /**
     * The Host header of the request does not steer what is announced: the origin is the issuer's.
     */
    #[Test]
    public function theEndpointsAreAnnouncedUnderTheIssuerNotUnderTheRequestHost(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration', server: [
            'HTTP_HOST' => 'attacker.example',
        ]);

        // Then
        static::assertSame('https://op.test/token', self::json($this->browser->getResponse())['token_endpoint']);
    }

    /**
     * Architecture §5.2: the endpoint locator the bundle binds is the one of the router.
     */
    #[Test]
    public function theRouterLocatesTheEndpoints(): void
    {
        // When
        $endpoints = self::service('test.beffroi.endpoints', EndpointLocatorInterface::class)->locate(self::tenant());

        // Then
        static::assertSame('https://op.test/authorize', $endpoints->authorization);
        static::assertSame('https://op.test/token', $endpoints->token);
    }

    #[Test]
    public function theMetadataIsReadOnly(): void
    {
        // When
        $this->browser->request('POST', '/.well-known/openid-configuration');

        // Then
        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }
}
