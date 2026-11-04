<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Identity\WiredClaims;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use App\Tests\Symfony\Functional\ResponseMode\InventedResponseModeRenderer;
use Beffroi\Oidc\Tests\Fixture\InventedClaimsProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC Discovery §4, Architecture §4.8, §5.2
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
     * RFC 8414 §3
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
     * Decision 0006, RFC 9207 §3
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
     * OIDC Discovery §3 "scopes_supported", OIDC Core §5.4, §11
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
     * OIDC Discovery §3 "claims_supported"
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
     * OIDC Core §5.1
     */
    #[Test]
    public function everyClaimAPersonMaySayOfThemselvesIsAnnouncedUnderThatName(): void
    {
        // Given
        $wired = self::service('test.beffroi.claims', WiredClaims::class)->names();

        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $claims = self::json($this->browser->getResponse())['claims_supported'];
        static::assertIsArray($claims);
        foreach ($wired as $name) {
            static::assertContains($name, $claims);
        }
    }

    /**
     * RFC 8705 §3.3, §5, Architecture §5.2
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
     * OIDC Discovery §3 "response_modes_supported", JARM §2.1, Form Post Response Mode §2, Decision 0006
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
     * JARM §3
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
     * OIDC Discovery §3, RFC 9101 §10.5
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
     * OIDC Discovery §3 "acr_values_supported", Decision 0010
     */
    #[Test]
    public function theMetadataAnnouncesTheClassesThePasswordAndThePasskeyProve(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame(['phrh', 'phr', '2', '1'], self::json($this->browser->getResponse())['acr_values_supported']);
    }

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
     * Architecture §5.2
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
