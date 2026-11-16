<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\AuthorizationRequest;
use Beffroi\Tui\Protocol\DpopProofs;
use Beffroi\Tui\Protocol\PrivateKeyJwt;
use Beffroi\Tui\Protocol\ProviderEndpoint;
use Beffroi\Tui\Protocol\ProviderRefusalException;
use Beffroi\Tui\Protocol\PushedAuthorization;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\Jwt;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * RFC 9126: the request is pushed, authenticated and proven, and the browser is sent with its reference alone.
 */
final class PushedAuthorizationTest extends TestCase
{
    private const string PUSHED = '{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}';

    /**
     * RFC 9126 §4, FAPI 2.0 Security Profile §5.3.3.2 item 6.
     */
    #[Test]
    public function theBrowserIsSentWithTheClientAndTheReferenceAlone(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse(self::PUSHED, ['http_code' => 201])]);

        // When
        $url = self::pushedAuthorization($http)->push(self::request());

        // Then
        static::assertSame('https://op.example/authorize?client_id=tui-client&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc', $url);
    }

    /**
     * RFC 9126 §2.1 and RFC 9449 §10.1: the client authenticates and the key of the run proves the request.
     */
    #[Test]
    public function thePushedRequestIsAuthenticatedAndProven(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse(self::PUSHED, ['http_code' => 201])]);

        // When
        self::pushedAuthorization($http)->push(self::request());

        // Then
        $request = $http->last();
        static::assertSame(
            ['https://op.example/par', PrivateKeyJwt::ASSERTION_TYPE, 'POST', 'https://op.example/par'],
            [
                $request['url'],
                $request['form']['client_assertion_type'] ?? null,
                Jwt::claims($request['headers']['dpop'] ?? '')->nullableString('htm'),
                Jwt::claims($request['headers']['dpop'] ?? '')->nullableString('htu'),
            ],
        );
    }

    /**
     * RFC 9449 §8: a provider that wants a nonce says so, and the request is sent again with it.
     */
    #[Test]
    public function aProviderThatAsksForANonceGetsItInTheNextProof(): void
    {
        // Given
        $http = RecordedRequests::answering([
            new MockResponse('{"error":"use_dpop_nonce"}', ['http_code' => 400, 'response_headers' => ['DPoP-Nonce' => 'n-1']]),
            new MockResponse(self::PUSHED, ['http_code' => 201]),
        ]);

        // When
        self::pushedAuthorization($http)->push(self::request());

        // Then
        static::assertSame('n-1', Jwt::claims($http->last()['headers']['dpop'] ?? '')->nullableString('nonce'));
    }

    #[Test]
    public function aRefusedRequestIsTheRefusalOfTheProvider(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"error":"invalid_request","error_description":"No."}', ['http_code' => 400])]);

        // Then
        $this->expectException(ProviderRefusalException::class);
        $this->expectExceptionMessageIs('The pushed authorization request endpoint refused the request (invalid_request): No.');

        // When
        self::pushedAuthorization($http)->push(self::request());
    }

    private static function pushedAuthorization(RecordedRequests $http): PushedAuthorization
    {
        $clock = new MockClock();

        return new PushedAuthorization(
            new ProviderEndpoint(
                $http->client,
                new PrivateKeyJwt(FakeProvider::CLIENT_ID, SigningKey::generate(), FakeProvider::ISSUER, $clock),
                new DpopProofs(SigningKey::generate(), $clock),
            ),
            FakeProvider::metadata(),
        );
    }

    private static function request(): AuthorizationRequest
    {
        return AuthorizationRequest::draw(FakeProvider::CLIENT_ID, FakeProvider::REDIRECT_URI, 'en', FakeProvider::ADMINISTRATION);
    }
}
