<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Api;

use function Amp\async;
use function Amp\delay;
use function Amp\Future\await;
use function array_filter;
use Beffroi\Tui\Protocol\AuthorizationRequest;
use Beffroi\Tui\Protocol\ProviderRefusalException;
use Beffroi\Tui\Protocol\UnreachableEndpointException;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\Jwt;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Tests\Fixture\Sessions;
use function count;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_ends_with;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

/**
 * The administration API is read with the tokens of the session: bound to the key of the run, under the DPoP scheme,
 * a nonce it asks for carried once, a token it refuses refreshed once.
 */
final class AdministrationApiTest extends TestCase
{
    private const string TENANT = FakeProvider::ADMINISTRATION . '/tenant';

    /**
     * RFC 9449 §7.1: a token bound to a key is presented under the DPoP scheme.
     */
    #[Test]
    public function aRequestCarriesTheAccessTokenUnderTheDpopScheme(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"slug":"default"}')]);

        // When
        Sessions::of($http->client)->api()->read('/tenant');

        // Then
        static::assertSame(['GET', self::TENANT, 'DPoP the-access-token'], [
            $http->last()['method'],
            $http->last()['url'],
            $http->last()['headers']['authorization'] ?? null,
        ]);
    }

    /**
     * RFC 9449 §4.2, §7.1: the proof names the method and the URI of the request without its query, and carries the
     * hash of the token it goes with.
     */
    #[Test]
    public function aRequestCarriesAProofMadeForItAndForTheToken(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{}')]);

        // When
        Sessions::of($http->client)->api()->read('/users', ['username' => 'alice']);

        // Then
        $claims = Jwt::claims($http->last()['headers']['dpop'] ?? '')->members;
        static::assertSame(
            ['GET', FakeProvider::ADMINISTRATION . '/users', AuthorizationRequest::s256('the-access-token')],
            [$claims['htm'] ?? null, $claims['htu'] ?? null, $claims['ath'] ?? null],
        );
    }

    /**
     * RFC 9449 §4.2: the proof of a request that removes a resource names its method.
     */
    #[Test]
    public function aDeletionCarriesAProofMadeForItsMethod(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"id":"session-1"}')]);

        // When
        Sessions::of($http->client)->api()->delete('/users/0193-alice/sessions/session-1');

        // Then
        static::assertSame(
            ['DELETE', 'DELETE', FakeProvider::ADMINISTRATION . '/users/0193-alice/sessions/session-1'],
            [
                $http->last()['method'],
                Jwt::claims($http->last()['headers']['dpop'] ?? '')->nullableString('htm'),
                Jwt::claims($http->last()['headers']['dpop'] ?? '')->nullableString('htu'),
            ],
        );
    }

    /**
     * RFC 9449 §4.2: the proof of a request that creates a resource names its method, and what it asks for is a JSON
     * object.
     */
    #[Test]
    public function aCreationCarriesWhatItAsksForAsJsonUnderAProofMadeForItsMethod(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"id":"0193-dave"}', ['http_code' => 201])]);

        // When
        Sessions::of($http->client)->api()->post('/users', ['username' => 'dave']);

        // Then
        static::assertSame(
            ['POST', 'POST', 'application/json', '{"username":"dave"}'],
            [
                $http->last()['method'],
                Jwt::claims($http->last()['headers']['dpop'] ?? '')->nullableString('htm'),
                $http->last()['headers']['content-type'] ?? null,
                $http->last()['body'],
            ],
        );
    }

    /**
     * RFC 9110 §9.3.4, RFC 9449 §4.2: a resource the path names is set without a body, under a proof made for its method.
     */
    #[Test]
    public function aStateIsSetWithoutABodyUnderAProofMadeForItsMethod(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"id":"0193-alice","enabled":false}')]);

        // When
        $answer = Sessions::of($http->client)->api()->put('/users/0193-alice/disabled');

        // Then
        static::assertSame(
            ['PUT', 'PUT', '', false],
            [
                $http->last()['method'],
                Jwt::claims($http->last()['headers']['dpop'] ?? '')->nullableString('htm'),
                $http->last()['body'],
                $answer->nullableBool('enabled'),
            ],
        );
    }

    /**
     * RFC 7396 §2, RFC 9449 §4.2: a change is a merge patch of the resource, under a proof made for its method.
     */
    #[Test]
    public function aChangeCarriesAMergePatchUnderAProofMadeForItsMethod(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"id":"0193-alice","username":"alice"}')]);

        // When
        Sessions::of($http->client)->api()->patch('/users/0193-alice', ['claims' => ['nickname' => 'Ali', 'address' => ['locality' => null]]]);

        // Then
        static::assertSame(
            ['PATCH', 'PATCH', 'application/merge-patch+json', '{"claims":{"nickname":"Ali","address":{"locality":null}}}'],
            [
                $http->last()['method'],
                Jwt::claims($http->last()['headers']['dpop'] ?? '')->nullableString('htm'),
                $http->last()['headers']['content-type'] ?? null,
                $http->last()['body'],
            ],
        );
    }

    /**
     * RFC 9110 §15.3.1: what the API changed it answers with 200; any other answer is no change.
     */
    #[Test]
    public function aChangeAnsweredWithAnotherStatusIsARefusal(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse(
            '{"error":"conflict","error_description":"The tenant has a person of this username already."}',
            ['http_code' => 409],
        )]);

        // Then
        $this->expectException(ProviderRefusalException::class);
        $this->expectExceptionMessageIs('The administration API refused the request (conflict): The tenant has a person of this username already.');

        // When
        Sessions::of($http->client)->api()->patch('/users/0193-alice', ['username' => 'bob']);
    }

    #[Test]
    public function aCreationThatAsksForNothingCarriesNoBody(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"link":"https://op.example/enrol/t-1/v-1"}', ['http_code' => 201])]);

        // When
        Sessions::of($http->client)->api()->post('/users/0193-alice/enrolment-ticket');

        // Then
        static::assertSame(['', null], [$http->last()['body'], $http->last()['headers']['content-type'] ?? null]);
    }

    /**
     * RFC 9110 §15.3.2: what the API created it answers with 201; any other answer is no creation.
     */
    #[Test]
    public function aCreationAnsweredWithAnotherStatusIsARefusal(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"id":"0193-dave"}')]);

        // Then
        $this->expectException(ProviderRefusalException::class);
        $this->expectExceptionMessageIs('The administration API refused the request (HTTP 200).');

        // When
        Sessions::of($http->client)->api()->post('/users', ['username' => 'dave']);
    }

    /**
     * RFC 6750 §3.1: a deletion the API refused for its token changed nothing, so it is sent again with the token refreshed.
     */
    #[Test]
    public function aDeletionRefusedForItsTokenIsSentAgainWithTheTokenRefreshed(): void
    {
        // Given
        $http = RecordedRequests::answering([
            self::challenged('DPoP error="invalid_token"'),
            self::refreshed(),
            new MockResponse('{"id":"session-1"}'),
        ]);

        // When
        Sessions::of($http->client, ['refresh_token' => 'the-refresh-token'])->api()->delete('/users/0193-alice/sessions/session-1');

        // Then
        static::assertSame(['DELETE', 'DPoP the-new-access-token'], [$http->last()['method'], $http->last()['headers']['authorization'] ?? null]);
    }

    /**
     * @param array<string, string> $query
     */
    #[Test]
    #[DataProvider('provideQueries')]
    public function theQueryIsEncodedAsAUriEncodesIt(array $query, string $url): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{}')]);

        // When
        Sessions::of($http->client)->api()->read('/users', $query);

        // Then
        static::assertSame($url, $http->last()['url']);
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function provideQueries(): iterable
    {
        yield 'a username' => [['username' => 'alice'], FakeProvider::ADMINISTRATION . '/users?username=alice'];
        yield 'a space and an ampersand, RFC 3986 §2.1' => [
            ['username' => 'ada lovelace&co'],
            FakeProvider::ADMINISTRATION . '/users?username=ada%20lovelace%26co',
        ];
        yield 'no query' => [[], FakeProvider::ADMINISTRATION . '/users'];
    }

    /**
     * RFC 9449 §9: the nonce the API asks for is in the proof of the request sent again.
     */
    #[Test]
    public function aNonceTheApiAsksForIsCarriedByTheRequestSentAgain(): void
    {
        // Given
        $http = RecordedRequests::answering([
            self::challenged('DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"', ['DPoP-Nonce' => 'the-nonce']),
            new MockResponse('{"slug":"default"}'),
        ]);

        // When
        $tenant = Sessions::of($http->client)->api()->read('/tenant');

        // Then
        static::assertSame(
            ['the-nonce', 'default', 2],
            [Jwt::claims($http->last()['headers']['dpop'] ?? '')->nullableString('nonce'), $tenant->nullableString('slug'), count($http->requests)],
        );
    }

    /**
     * RFC 9449 §9: a nonce is asked for once; an API that asks again is refused rather than asked forever.
     */
    #[Test]
    public function anApiThatAsksForANonceAgainIsARefusal(): void
    {
        // Given
        $http = RecordedRequests::answering([
            self::challenged('DPoP error="use_dpop_nonce"', ['DPoP-Nonce' => 'one']),
            self::challenged('DPoP error="use_dpop_nonce"', ['DPoP-Nonce' => 'two']),
            new MockResponse('{"slug":"default"}'),
        ]);

        // Then
        $this->expectException(ProviderRefusalException::class);

        // When
        Sessions::of($http->client)->api()->read('/tenant');
    }

    /**
     * RFC 6750 §3.1, RFC 6749 §6: a token the API refuses is refreshed, and the request sent again with the new one.
     */
    #[Test]
    public function aTokenTheApiRefusesIsRefreshedAndTheRequestSentAgain(): void
    {
        // Given
        $http = RecordedRequests::answering([
            self::challenged('DPoP error="invalid_token", error_description="The access token expired."'),
            self::refreshed(),
            new MockResponse('{"slug":"default"}'),
        ]);

        // When
        Sessions::of($http->client, ['refresh_token' => 'the-refresh-token'])->api()->read('/tenant');

        // Then
        static::assertSame(
            [FakeProvider::ISSUER . '/token', 'refresh_token', 'the-refresh-token', 'DPoP the-new-access-token'],
            [
                $http->requests[1]['url'],
                RecordedRequests::field($http->requests[1], 'grant_type'),
                RecordedRequests::field($http->requests[1], 'refresh_token'),
                $http->last()['headers']['authorization'] ?? null,
            ],
        );
    }

    /**
     * RFC 9449 §5: the refresh proves the key of the run, so that the access token it answers is bound to it as well.
     */
    #[Test]
    public function theRefreshProvesTheKeyOfTheRun(): void
    {
        // Given
        $http = RecordedRequests::answering([
            self::challenged('DPoP error="invalid_token"'),
            self::refreshed(),
            new MockResponse('{}'),
        ]);

        // When
        Sessions::of($http->client, ['refresh_token' => 'the-refresh-token'])->api()->read('/tenant');

        // Then
        static::assertSame(
            ['POST', FakeProvider::ISSUER . '/token'],
            [
                Jwt::claims($http->requests[1]['headers']['dpop'] ?? '')->nullableString('htm'),
                Jwt::claims($http->requests[1]['headers']['dpop'] ?? '')->nullableString('htu'),
            ],
        );
    }

    /**
     * An access token about to expire is refreshed before the request, rather than refused by it.
     */
    #[Test]
    public function anAccessTokenAboutToExpireIsRefreshedBeforeTheRequest(): void
    {
        // Given
        $http = RecordedRequests::answering([self::refreshed(), new MockResponse('{}')]);
        $clock = new MockClock(new DateTimeImmutable('@' . (FakeProvider::NOW + 290)));

        // When
        Sessions::of($http->client, ['refresh_token' => 'the-refresh-token'], clock: $clock)->api()->read('/tenant');

        // Then
        static::assertSame(
            [FakeProvider::ISSUER . '/token', 'DPoP the-new-access-token'],
            [$http->requests[0]['url'], $http->last()['headers']['authorization'] ?? null],
        );
    }

    /**
     * Two sections read at once with a token about to expire refresh the session once, the second waiting for the
     * first.
     */
    #[Test]
    public function twoReadsAtOnceRefreshTheSessionOnce(): void
    {
        // Given
        $http = RecordedRequests::answering([self::refreshed(), new MockResponse('{}'), new MockResponse('{}')]);
        $clock = new MockClock(new DateTimeImmutable('@' . (FakeProvider::NOW + 290)));
        $api = Sessions::of(self::slow($http->client), ['refresh_token' => 'the-refresh-token'], clock: $clock)->api();

        // When
        await([async(static fn () => $api->read('/tenant')), async(static fn () => $api->read('/keys'))]);

        // Then
        static::assertCount(1, array_filter($http->requests, static fn (array $request): bool => str_ends_with($request['url'], '/token')));
    }

    /**
     * A session the provider handed no refresh token keeps its token, and the refusal of the API is what is said.
     */
    #[Test]
    public function withoutARefreshTokenARefusedTokenIsTheRefusal(): void
    {
        // Given
        $http = RecordedRequests::answering([self::challenged('DPoP error="invalid_token", error_description="The access token expired."')]);

        // Then
        $this->expectException(ProviderRefusalException::class);
        $this->expectExceptionMessageIs('The administration API refused the request (invalid_token): The access token expired.');

        // When
        Sessions::of($http->client)->api()->read('/tenant');
    }

    /**
     * RFC 6750 §3: the resource says why it refused a token in its challenge, the body saying nothing.
     */
    #[Test]
    public function aRefusalCarriesWhatTheChallengeSays(): void
    {
        // Given
        $http = RecordedRequests::answering([self::challenged('DPoP algs="ES256", error="invalid_dpop_proof", error_description="The \"htu\" does not match."')]);

        // When
        try {
            Sessions::of($http->client)->api()->read('/tenant');
            $refusal = null;
        } catch (ProviderRefusalException $exception) {
            $refusal = $exception;
        }

        // Then
        static::assertSame([401, 'invalid_dpop_proof', 'The "htu" does not match.'], [$refusal?->status, $refusal?->error, $refusal?->description]);
    }

    /**
     * What the API answers in its body is what a refusal says first.
     */
    #[Test]
    public function aRefusalCarriesWhatTheBodySays(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"error":"not_found","error_description":"No user is named so."}', ['http_code' => 404])]);

        // When
        try {
            Sessions::of($http->client)->api()->read('/users', ['username' => 'nobody']);
            $refusal = null;
        } catch (ProviderRefusalException $exception) {
            $refusal = $exception;
        }

        // Then
        static::assertSame([404, 'not_found'], [$refusal?->status, $refusal?->error]);
    }

    #[Test]
    public function anApiThatAnswersNothingIsUnreachable(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('', ['error' => 'Could not resolve host: admin.op.example'])]);

        // Then
        $this->expectException(UnreachableEndpointException::class);
        $this->expectExceptionMessageIsOrContains('The administration API cannot be reached');

        // When
        Sessions::of($http->client)->api()->read('/tenant');
    }

    /**
     * @param array<string, string> $headers
     */
    private static function challenged(string $challenge, array $headers = []): MockResponse
    {
        return new MockResponse('', [
            'http_code' => 401,
            'response_headers' => [
                ...$headers,
                'WWW-Authenticate' => $challenge,
            ],
        ]);
    }

    private static function refreshed(): MockResponse
    {
        return new MockResponse('{"access_token":"the-new-access-token","token_type":"DPoP","expires_in":300,"refresh_token":"the-new-refresh-token"}');
    }

    /**
     * A client that gives the event loop a turn before each request, as a request over the network does.
     */
    private static function slow(HttpClientInterface $client): HttpClientInterface
    {
        return new readonly class($client) implements HttpClientInterface {
            public function __construct(
                private HttpClientInterface $client,
            ) {
            }

            /**
             * @param array<array-key, mixed> $options
             */
            public function request(string $method, string $url, array $options = []): ResponseInterface
            {
                delay(0.001);

                return $this->client->request($method, $url, $options);
            }

            public function stream(ResponseInterface|iterable $responses, ?float $timeout = null): ResponseStreamInterface
            {
                return $this->client->stream($responses, $timeout);
            }

            /**
             * @param array<array-key, mixed> $options
             */
            public function withOptions(array $options): static
            {
                return $this;
            }
        };
    }
}
