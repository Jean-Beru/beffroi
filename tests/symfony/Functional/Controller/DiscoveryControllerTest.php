<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Oidc\Port\EndpointLocatorInterface;
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
     * OIDC Discovery §3 "response_modes_supported", issue #98: the ways of answering wired into the
     * authorization endpoint of the bundle, the default one and the posted form (Form Post Response Mode
     * §2); the response types stay "code" alone, in every mode (decision 0006).
     */
    #[Test]
    public function theMetadataAnnouncesTheResponseModesTheBundleWires(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame(['query', 'form_post'], $metadata['response_modes_supported']);
        static::assertSame(['code'], $metadata['response_types_supported']);
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
        $endpoints = self::service('test.heidi.endpoints', EndpointLocatorInterface::class)->locate(self::tenant());

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
