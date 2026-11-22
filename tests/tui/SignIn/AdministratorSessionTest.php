<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\SignIn;

use Beffroi\Tui\Protocol\Identity;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Tests\Fixture\Sessions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * A session ends with the run: its tokens are handed back to the provider (RFC 7009).
 */
final class AdministratorSessionTest extends TestCase
{
    /**
     * RFC 7009 §2.1: the refresh token first, whose revocation takes the access tokens of its grant along.
     */
    #[Test]
    public function endingTheSessionHandsBackTheRefreshTokenThenTheAccessToken(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse(''), new MockResponse('')]);
        $session = Sessions::of($http->client, ['refresh_token' => 'the-refresh-token']);

        // When
        $session->end();

        // Then
        static::assertSame(
            [
                ['the-refresh-token', 'refresh_token'],
                ['the-access-token',  'access_token'],
            ],
            [
                [RecordedRequests::field($http->requests[0], 'token'), RecordedRequests::field($http->requests[0], 'token_type_hint')],
                [RecordedRequests::field($http->requests[1], 'token'), RecordedRequests::field($http->requests[1], 'token_type_hint')],
            ],
        );
    }

    /**
     * RFC 7009 §2.2.1: a self-contained access token is one the provider may not take back, which it says, and which is
     * nothing to tell: the token is bound to a key nobody holds once the run is over, and it expires on its own.
     */
    #[Test]
    public function anAccessTokenTheProviderDoesNotRevokeIsNoRefusal(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"error":"unsupported_token_type","error_description":"It expires on its own."}', [
            'http_code' => 400,
        ])]);

        // When
        $refusals = Sessions::of($http->client)->end();

        // Then
        static::assertSame([], $refusals);
    }

    /**
     * RFC 7009 §2: a provider takes a refresh token back, so one it does not is said, in its words.
     */
    #[Test]
    public function aRefreshTokenTheProviderDoesNotRevokeIsSaid(): void
    {
        // Given
        $http = RecordedRequests::answering([
            new MockResponse('{"error":"unsupported_token_type","error_description":"Not this one."}', ['http_code' => 400]),
            new MockResponse(''),
        ]);

        // When
        $refusals = Sessions::of($http->client, ['refresh_token' => 'the-refresh-token'])->end();

        // Then
        static::assertSame(['The revocation endpoint refused the request (unsupported_token_type): Not this one.'], $refusals);
    }

    /**
     * OIDC Core §5.5: the name the request asked the ID token for, then the username, then the subject.
     *
     * @param array{?string, ?string} $names
     */
    #[Test]
    #[DataProvider('provideIdTokens')]
    public function theAdministratorIsNamedByTheIdToken(array $names, string $named): void
    {
        // Given
        $session = Sessions::of(new MockHttpClient(), identity: new Identity('administrator', 'phr', ['hwk'], null, ...$names));

        // When / Then
        static::assertSame($named, $session->administratorName());
    }

    /**
     * @return iterable<string, array{array{?string, ?string}, string}>
     */
    public static function provideIdTokens(): iterable
    {
        yield 'a name' => [['Ada Lovelace', 'ada'], 'Ada Lovelace'];
        yield 'a username alone' => [[null, 'ada'], 'ada'];
        yield 'neither' => [[null, null], 'administrator'];
    }

    /**
     * RFC 7009 §2.1: the tokens handed back are the ones the session holds when it ends, which a refresh replaced.
     */
    #[Test]
    public function endingTheSessionHandsBackTheTokensItHoldsLast(): void
    {
        // Given
        $http = RecordedRequests::answering([
            new MockResponse('', ['http_code' => 401, 'response_headers' => ['WWW-Authenticate' => 'DPoP error="invalid_token"']]),
            new MockResponse('{"access_token":"the-new-access-token","token_type":"DPoP","expires_in":300,"refresh_token":"the-new-refresh-token"}'),
            new MockResponse('{}'),
            new MockResponse(''),
            new MockResponse(''),
        ]);
        $session = Sessions::of($http->client, ['refresh_token' => 'the-refresh-token']);
        $session->api()->read('/tenant');

        // When
        $session->end();

        // Then
        static::assertSame(
            ['the-new-refresh-token', 'the-new-access-token'],
            [RecordedRequests::field($http->requests[3], 'token'), RecordedRequests::field($http->requests[4], 'token')],
        );
    }

    /**
     * RFC 6749 §6: a refresh that answers no refresh token leaves the session with the one it held, which it hands back.
     */
    #[Test]
    public function aRefreshThatAnswersNoRefreshTokenLeavesTheOneHeld(): void
    {
        // Given
        $http = RecordedRequests::answering([
            new MockResponse('{"access_token":"the-new-access-token","token_type":"DPoP","expires_in":300}'),
            new MockResponse('{}'),
            new MockResponse(''),
            new MockResponse(''),
        ]);
        $clock = new MockClock(new DateTimeImmutable('@' . (FakeProvider::NOW + 290)));
        $session = Sessions::of($http->client, ['refresh_token' => 'the-refresh-token'], clock: $clock);
        $session->api()->read('/tenant');

        // When
        $session->end();

        // Then
        static::assertSame('the-refresh-token', RecordedRequests::field($http->requests[2], 'token'));
    }

    /**
     * The expiry the screen shows is the one of the access token held, which a refresh moves.
     */
    #[Test]
    public function theExpiryIsTheOneOfTheTokenHeld(): void
    {
        // Given
        $http = RecordedRequests::answering([
            new MockResponse('{"access_token":"the-new-access-token","token_type":"DPoP","expires_in":600}'),
            new MockResponse('{}'),
        ]);
        $clock = new MockClock(new DateTimeImmutable('@' . (FakeProvider::NOW + 290)));
        $session = Sessions::of($http->client, ['refresh_token' => 'the-refresh-token'], clock: $clock);

        // When
        $session->api()->read('/tenant');

        // Then
        static::assertSame(FakeProvider::NOW + 290 + 600, $session->expiresAt()?->getTimestamp());
    }
}
