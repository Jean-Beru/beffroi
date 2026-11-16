<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\SignIn;

use Amp\TimeoutCancellation;
use function Amp\async;
use function Amp\ByteStream\buffer;
use function Amp\Socket\connect;
use function Amp\Socket\listen;
use ArrayObject;
use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\AuthorizationRequest;
use Beffroi\Tui\Protocol\RejectedAnswerException;
use Beffroi\Tui\Provider\ProviderMetadataReader;
use Beffroi\Tui\SignIn\AdministratorSession;
use Beffroi\Tui\SignIn\BrowserInterface;
use Beffroi\Tui\SignIn\CannotListenException;
use Beffroi\Tui\SignIn\LoopbackListener;
use Beffroi\Tui\SignIn\PendingSignIn;
use Beffroi\Tui\SignIn\SignIn;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\Jwt;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use DateTimeImmutable;
use function array_fill;
use function array_map;
use function explode;
use function http_build_query;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_ends_with;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The whole sign-in against a provider that answers what a provider answers: the request pushed, the browser
 * back on the loopback interface, the code exchanged with a proof of the key the tokens are bound to, the ID token
 * validated.
 */
final class SignInTest extends TestCase
{
    private RecordedRequests $http;

    /**
     * @var ArrayObject<string, mixed> the claims the ID token carries in place of those of `FakeProvider::claims()`
     */
    private ArrayObject $replacingClaims;

    protected function setUp(): void
    {
        $provider = new FakeProvider();
        $replacing = $this->replacingClaims = new ArrayObject();
        $this->http = RecordedRequests::routed(static fn (string $method, string $url, RecordedRequests $sent): MockResponse => match (true) {
            str_ends_with($url, '/.well-known/openid-configuration') => new MockResponse(json_encode(FakeProvider::metadataDocument(), JSON_THROW_ON_ERROR)),
            str_ends_with($url, '/par') => new MockResponse('{"request_uri":"urn:ietf:params:oauth:request_uri:r","expires_in":60}', ['http_code' => 201]),
            str_ends_with($url, '/token') => new MockResponse(json_encode([
                'access_token' => 'the-access-token',
                'token_type' => 'DPoP',
                'expires_in' => 300,
                'id_token' => $provider->idToken(FakeProvider::claims(
                    RecordedRequests::field($sent->to('POST', FakeProvider::ISSUER . '/par'), 'nonce'),
                    ['name' => 'Ada Lovelace', ...$replacing->getArrayCopy()],
                )),
            ], JSON_THROW_ON_ERROR)),
            str_ends_with($url, '/revoke') => new MockResponse(''),
            str_ends_with($url, '/jwks') => new MockResponse($provider->jwks()),
            default => new MockResponse('', ['http_code' => 404]),
        });
    }

    #[Test]
    public function aSignInEndsInTheSessionOfTheAdministrator(): void
    {
        // When
        $session = $this->signIn();

        // Then
        static::assertSame(
            ['administrator', 'phr', 'Ada Lovelace'],
            [$session->identity->subject, $session->identity->authenticationClass, $session->administratorName()],
        );
    }

    /**
     * RFC 7636 §4.5: the code is exchanged with the verifier of the challenge the request was pushed with.
     */
    #[Test]
    public function theCodeIsExchangedWithTheVerifierOfThePushedChallenge(): void
    {
        // When
        $this->signIn();

        // Then
        $exchanged = $this->http->to('POST', FakeProvider::ISSUER . '/token');
        static::assertSame(
            [$this->pushed('code_challenge'), 'the-code'],
            [AuthorizationRequest::s256(RecordedRequests::field($exchanged, 'code_verifier')), RecordedRequests::field($exchanged, 'code')],
        );
    }

    /**
     * RFC 9449 §10.1 and §5: one key proves the pushed request and the exchange, the one the tokens are bound to.
     */
    #[Test]
    public function oneKeyProvesThePushedRequestAndTheExchange(): void
    {
        // When
        $session = $this->signIn();

        // Then
        $thumbprints = [];
        foreach ([['POST', '/par'], ['POST', '/token']] as [$method, $path]) {
            $key = Jwt::header($this->http->to($method, FakeProvider::ISSUER . $path)['headers']['dpop'] ?? '')->nested('jwk')->members ?? [];
            $thumbprints[] = new JWK($key)->thumbprint('sha256');
        }
        static::assertSame(array_fill(0, 2, $session->proofs->thumbprint()), $thumbprints);
    }

    /**
     * RFC 7009 §2.1: the tokens of a sign-in a later step refuses are handed back rather than left valid.
     */
    #[Test]
    public function theTokensOfASignInThatDoesNotHoldAreHandedBack(): void
    {
        // Given
        $this->replacingClaims['acr'] = '1';

        // When
        try {
            $this->signIn();
            static::fail('A password login made an administrator\'s session.');
        } catch (RejectedAnswerException) {
        }

        // Then
        static::assertSame('the-access-token', RecordedRequests::field($this->http->to('POST', FakeProvider::ISSUER . '/revoke'), 'token'));
    }

    /**
     * The port the client registered is bound before anything is asked of the provider.
     */
    #[Test]
    public function aPortSomethingElseHoldsStopsTheSignInBeforeTheRequestIsPushed(): void
    {
        // Given
        $taken = listen('127.0.0.1:0');
        $port = (int) explode(':', $taken->getAddress()->toString())[1];

        // When
        try {
            $this->started($port);
            static::fail('The sign-in started on a port something else holds.');
        } catch (CannotListenException) {
        }

        // Then
        static::assertSame(
            [['GET', FakeProvider::ISSUER . '/.well-known/openid-configuration']],
            array_map(static fn (array $request): array => [$request['method'], $request['url']], $this->http->requests),
        );
    }

    private function signIn(): AdministratorSession
    {
        $port = self::freePort();
        $pending = $this->started($port);
        $completion = async(static fn (): AdministratorSession => $pending->complete());
        $socket = connect(sprintf('127.0.0.1:%d', $port));
        $socket->write(sprintf("GET /callback?%s HTTP/1.1\r\n\r\n", http_build_query([
            'code' => 'the-code',
            'state' => $this->pushed('state'),
            'iss' => FakeProvider::ISSUER,
        ])));
        buffer($socket, new TimeoutCancellation(5));
        $session = $completion->await(new TimeoutCancellation(5));
        if (! $session instanceof AdministratorSession) {
            static::fail('The sign-in ended in no session.');
        }

        return $session;
    }

    private function started(int $port): PendingSignIn
    {
        $browser = new class implements BrowserInterface {
            public function open(string $url): void
            {
            }
        };

        return new SignIn(
            new ProviderMetadataReader($this->http->client),
            $this->http->client,
            new MockClock(new DateTimeImmutable('@' . FakeProvider::NOW)),
            $browser,
            '<p>back</p>',
        )->start(FakeProvider::profile(SigningKey::generate(), sprintf('http://127.0.0.1:%d/callback', $port)), 'en');
    }

    /**
     * A field of the pushed request.
     */
    private function pushed(string $name): string
    {
        return RecordedRequests::field($this->http->to('POST', FakeProvider::ISSUER . '/par'), $name);
    }

    private static function freePort(): int
    {
        $listener = LoopbackListener::on('http://127.0.0.1:0/callback', '');
        $port = $listener->port();
        $listener->close();

        return $port;
    }
}
