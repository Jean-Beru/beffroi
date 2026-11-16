<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\SignIn;

use Amp\ByteStream\StreamException;
use Amp\Future;
use Amp\Socket\Socket;
use Amp\TimeoutCancellation;
use function Amp\async;
use function Amp\ByteStream\buffer;
use function Amp\Socket\connect;
use function Amp\Socket\listen;
use Beffroi\Tui\Protocol\AuthorizationResponse;
use Beffroi\Tui\SignIn\CannotListenException;
use Beffroi\Tui\SignIn\LoopbackListener;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * RFC 8252 §7.3 and §8.3: the response comes back to the loopback interface, at the path the client registered,
 * and the listener waits for the response to the request and for nothing else.
 */
final class LoopbackListenerTest extends TestCase
{
    private const string CALLBACK = 'http://127.0.0.1:0/callback';

    private const string STATE = 'drawn-state';

    private const string RESPONSE = "GET /callback?code=c&state=drawn-state&iss=https%3A%2F%2Fop.example HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

    private LoopbackListener $listener;

    /**
     * @var Future<string>
     */
    private Future $redirection;

    protected function setUp(): void
    {
        $listener = LoopbackListener::on(self::CALLBACK, '<p>back</p>');
        $this->listener = $listener;
        $this->redirection = async(static fn (): string => $listener->awaitRedirection(
            static fn (string $query): bool => AuthorizationResponse::carriesState($query, self::STATE),
        ));
    }

    protected function tearDown(): void
    {
        $this->listener->close();
    }

    #[Test]
    public function theQueryOfTheResponseIsWhatTheListenerWaitedFor(): void
    {
        // When
        $this->browse(self::RESPONSE);

        // Then
        static::assertSame('code=c&state=drawn-state&iss=https%3A%2F%2Fop.example', $this->redirection->await(new TimeoutCancellation(5)));
    }

    /**
     * Anything but the response is answered and changes nothing: the listener still waits for it.
     */
    #[Test]
    #[DataProvider('provideStrayRequests')]
    public function aStrayRequestIsAnsweredAndTheListenerKeepsWaiting(string $stray, string $status): void
    {
        // When
        $answer = $this->browse($stray);
        $this->browse(self::RESPONSE);

        // Then
        static::assertSame([$status, 'code=c&state=drawn-state&iss=https%3A%2F%2Fop.example'], [
            explode("\r\n", $answer)[0],
            $this->redirection->await(new TimeoutCancellation(5)),
        ]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideStrayRequests(): iterable
    {
        yield 'another path' => ["GET /favicon.ico HTTP/1.1\r\n\r\n", 'HTTP/1.1 404 Not Found'];
        yield 'a path that starts the same' => ["GET /callbacks?state=drawn-state HTTP/1.1\r\n\r\n", 'HTTP/1.1 404 Not Found'];
        yield 'another method' => ["POST /callback?state=drawn-state HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 'HTTP/1.1 404 Not Found'];
        yield 'no request line' => ["hello\r\n\r\n", 'HTTP/1.1 404 Not Found'];
        yield 'the path without the state, which anybody on this machine can send' => ["GET /callback HTTP/1.1\r\n\r\n", 'HTTP/1.1 400 Bad Request'];
        yield 'the path with another state' => ["GET /callback?code=forged&state=guessed HTTP/1.1\r\n\r\n", 'HTTP/1.1 400 Bad Request'];
        yield 'the state written twice' => ["GET /callback?state=drawn-state&state=other HTTP/1.1\r\n\r\n", 'HTTP/1.1 400 Bad Request'];
    }

    /**
     * The page refers nothing, loads nothing, is kept by nobody and is framed by nobody: the code in its URL goes
     * nowhere else.
     */
    #[Test]
    public function thePageOfTheResponseLeaksNothing(): void
    {
        // When
        $answer = $this->browse(self::RESPONSE);

        // Then
        static::assertSame(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 11\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n<p>back</p>",
            $answer,
        );
    }

    /**
     * Each connection holds a fiber and a descriptor for a few seconds at most, and a few dozen of them at a time.
     */
    #[Test]
    public function aConnectionBeyondTheFewDozenOpenAtATimeIsClosedUnanswered(): void
    {
        // Given
        $idle = [];
        for ($connection = 0; $connection < 32; ++$connection) {
            $idle[] = $this->connect();
        }

        // When
        $answer = $this->browse(self::RESPONSE);

        // Then
        foreach ($idle as $socket) {
            $socket->close();
        }
        static::assertSame('', $answer);
    }

    /**
     * RFC 8252 §7.3 and §8.3: the loopback interface by its IP literal, over HTTP, with a port.
     */
    #[Test]
    #[DataProvider('provideAddressesThatAreNotTheLoopbackInterface')]
    public function anAddressThatIsNotTheLoopbackInterfaceIsNotListenedOn(string $redirectUri): void
    {
        // Then
        $this->expectException(CannotListenException::class);

        // When
        LoopbackListener::on($redirectUri, '');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAddressesThatAreNotTheLoopbackInterface(): iterable
    {
        yield 'a name' => ['http://localhost:47613/callback'];
        yield 'HTTPS' => ['https://127.0.0.1:47613/callback'];
        yield 'no port' => ['http://127.0.0.1/callback'];
        yield 'another address' => ['http://192.0.2.1:47613/callback'];
    }

    #[Test]
    public function aPortSomethingElseHoldsIsNotListenedOn(): void
    {
        // Given
        $taken = listen('127.0.0.1:0');
        $port = (int) explode(':', $taken->getAddress()->toString())[1];

        // Then
        $this->expectException(CannotListenException::class);

        // When
        LoopbackListener::on(sprintf('http://127.0.0.1:%d/callback', $port), '');
    }

    private function connect(): Socket
    {
        return connect(sprintf('127.0.0.1:%d', $this->listener->port()));
    }

    private function browse(string $request): string
    {
        $socket = $this->connect();

        try {
            $socket->write($request);
        } catch (StreamException) {
            // a connection the listener closed unanswered takes nothing
        }

        return buffer($socket, new TimeoutCancellation(5));
    }
}
