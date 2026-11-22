<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Protocol;

use Beffroi\Tui\Json\Document;
use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\ClientRegistrationRequest;
use Beffroi\Tui\Protocol\Registration;
use Beffroi\Tui\Protocol\RejectedAnswerException;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * RFC 7591 §3.1: this program registers itself as a confidential client of one installation, and refuses to be
 * registered as anything else.
 */
final class RegistrationTest extends TestCase
{
    private const string REDIRECT_URI = 'http://127.0.0.1:47613/callback';

    /**
     * RFC 7591 §3: the initial access token is presented as a bearer token; RFC 8252 §8.4: the client holds a key
     * of its own and no secret. It registers no resource: the token the tenant issued for its administration gives
     * it the administration API (decision 0038).
     */
    #[Test]
    public function theClientRegistersItsPublicKeyWithTheInitialAccessToken(): void
    {
        // Given
        $key = SigningKey::generate();
        $request = new ClientRegistrationRequest('Beffroi TUI on desk', self::REDIRECT_URI, $key, 'ES256');
        $http = RecordedRequests::answering([new MockResponse(self::registered($request), ['http_code' => 201])]);

        // When
        new Registration($http->client)->register(FakeProvider::ISSUER . '/register', $request, 'initial-token');

        // Then
        $sent = Document::decode($http->last()['body'], 'registration');
        static::assertSame(
            ['Bearer initial-token', 'private_key_jwt', [$key->publicJwk()], true, [self::REDIRECT_URI], null],
            [
                $http->last()['headers']['authorization'] ?? null,
                $sent->nullableString('token_endpoint_auth_method'),
                $sent->nested('jwks')?->members['keys'] ?? null,
                $sent->isTrue('require_pushed_authorization_requests'),
                $sent->strings('redirect_uris'),
                $sent->members['resources'] ?? null,
            ],
        );
    }

    #[Test]
    public function whatRfc7592HandsOverIsKeptWithTheClient(): void
    {
        // Given
        $request = new ClientRegistrationRequest('Beffroi TUI on desk', self::REDIRECT_URI, SigningKey::generate(), 'ES256');
        $http = RecordedRequests::answering([new MockResponse(self::registered($request), ['http_code' => 201])]);

        // When
        $client = new Registration($http->client)->register(FakeProvider::ISSUER . '/register', $request, null);

        // Then
        static::assertSame(
            ['registered-client', 'https://op.example/register/registered-client', 'registration-token'],
            [$client->clientId, $client->registrationClientUri, $client->registrationAccessToken],
        );
    }

    /**
     * RFC 7591 §3.2.1: a provider may register other values than it was sent, and those are not this client.
     *
     * @param array<string, mixed> $replacing
     */
    #[Test]
    #[DataProvider('provideRegistrationsThisProgramDoesNotUse')]
    public function aClientRegisteredAsSomethingElseIsRejected(array $replacing, string $reason): void
    {
        // Given
        $request = new ClientRegistrationRequest('Beffroi TUI on desk', self::REDIRECT_URI, SigningKey::generate(), 'ES256');
        $http = RecordedRequests::answering([new MockResponse(self::registered($request, $replacing), ['http_code' => 201])]);

        // Then
        $this->expectException(RejectedAnswerException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new Registration($http->client)->register(FakeProvider::ISSUER . '/register', $request, null);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideRegistrationsThisProgramDoesNotUse(): iterable
    {
        yield 'with a secret' => [['token_endpoint_auth_method' => 'client_secret_basic', 'client_secret' => 's'], 'and not with its key'];
        yield 'another redirect URI' => [['redirect_uris' => ['http://127.0.0.1:1/callback']], 'other redirect URIs'];
        yield 'without pushed requests' => [['require_pushed_authorization_requests' => false], 'pushed requests'];
        yield 'another ID token algorithm' => [['id_token_signed_response_alg' => 'RS256'], '"RS256" and not "ES256"'];
    }

    /**
     * @param array<string, mixed> $replacing
     */
    private static function registered(ClientRegistrationRequest $request, array $replacing = []): string
    {
        return json_encode([
            ...$request->metadata(),
            'client_id' => 'registered-client',
            'registration_client_uri' => 'https://op.example/register/registered-client',
            'registration_access_token' => 'registration-token',
            ...$replacing,
        ], JSON_THROW_ON_ERROR);
    }
}
