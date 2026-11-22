<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Provider;

use Beffroi\Tui\Provider\ProviderMetadataReader;
use Beffroi\Tui\Provider\UnsuitableProviderException;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * This program talks to a provider that announces what an administrator's sign-in is held to, and to no other.
 */
final class ProviderMetadataReaderTest extends TestCase
{
    /**
     * OpenID Connect Discovery 1.0 §4: the document is under the issuer, its terminating slash removed.
     */
    #[Test]
    public function theMetadataAreReadUnderTheIssuer(): void
    {
        // Given
        $response = new MockResponse(json_encode(FakeProvider::metadataDocument(['issuer' => 'https://op.example/tenant/']), JSON_THROW_ON_ERROR));

        // When
        new ProviderMetadataReader(new MockHttpClient($response))->read('https://op.example/tenant/');

        // Then
        static::assertSame('https://op.example/tenant/.well-known/openid-configuration', $response->getRequestUrl());
    }

    /**
     * FAPI 2.0 Security Profile §5.3.3.1, item 9: the endpoints are those of the document; §5.4.1: an ID token is
     * signed with ES256, EdDSA or PS256, the first this program prefers among those the provider lists.
     */
    #[Test]
    public function theEndpointsAndTheAlgorithmsAreThoseOfTheDocument(): void
    {
        // Given
        $http = new MockHttpClient(new MockResponse(json_encode(FakeProvider::metadataDocument(), JSON_THROW_ON_ERROR)));

        // When
        $metadata = new ProviderMetadataReader($http)->read(FakeProvider::ISSUER);

        // Then
        static::assertEquals(FakeProvider::metadata(), $metadata);
    }

    /**
     * @param array<string, mixed> $replacing
     */
    #[Test]
    #[DataProvider('provideProvidersThisProgramDoesNotTalkTo')]
    public function aProviderThatDoesNotAnnounceWhatTheSignInNeedsIsRefused(array $replacing, string $reason): void
    {
        // Given
        $http = new MockHttpClient(new MockResponse(json_encode(FakeProvider::metadataDocument($replacing), JSON_THROW_ON_ERROR)));

        // Then
        $this->expectException(UnsuitableProviderException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new ProviderMetadataReader($http)->read(FakeProvider::ISSUER);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideProvidersThisProgramDoesNotTalkTo(): iterable
    {
        yield 'another issuer (Discovery §4.3)' => [['issuer' => 'https://evil.example'], 'name another issuer'];
        yield 'no iss in its responses (RFC 9207 §3)' => [['authorization_response_iss_parameter_supported' => false], 'name their issuer'];
        yield 'iss support said by a string' => [['authorization_response_iss_parameter_supported' => 'true'], 'must be a boolean'];
        yield 'no S256 (RFC 7636 §4.2)' => [['code_challenge_methods_supported' => ['plain']], '"S256"'];
        yield 'no private_key_jwt (OIDC Core §9)' => [['token_endpoint_auth_methods_supported' => ['client_secret_basic']], '"private_key_jwt"'];
        yield 'no ES256 assertion' => [['token_endpoint_auth_signing_alg_values_supported' => ['RS256']], 'token_endpoint_auth_signing_alg_values_supported'];
        yield 'no ES256 proof (RFC 9449 §5.1)' => [['dpop_signing_alg_values_supported' => ['RS256']], 'dpop_signing_alg_values_supported'];
        yield 'no phishing-resistant class (decision 0038)' => [['acr_values_supported' => ['1', '2']], '"phr"'];
        yield 'no FAPI 2.0 ID token algorithm (§5.4.1)' => [['id_token_signing_alg_values_supported' => ['RS256']], 'PS256, ES256 and EdDSA'];
        yield 'no pushed requests (RFC 9126)' => [['pushed_authorization_request_endpoint' => null], '"pushed_authorization_request_endpoint"'];
        yield 'a token endpoint in the clear' => [['token_endpoint' => 'http://op.example/token'], 'not an HTTPS URL'];
    }

    #[Test]
    public function anIssuerInTheClearIsNotAskedAnything(): void
    {
        // Given
        $http = new MockHttpClient();

        // When
        try {
            new ProviderMetadataReader($http)->read('http://op.example');
        } catch (UnsuitableProviderException) {
        }

        // Then
        static::assertSame(0, $http->getRequestsCount());
    }
}
