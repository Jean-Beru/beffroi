<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use Heidi\Oidc\Domain\Client\InitiateLoginUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class InitiateLoginUriTest extends TestCase
{
    /**
     * OIDC Registration §2: an "https" URL, kept as it was registered.
     */
    #[Test]
    public function itAcceptsAnHttpsUrl(): void
    {
        // When / Then
        static::assertSame('https://rp.example/start?app=1', (string) new InitiateLoginUri('https://rp.example/start?app=1'));
    }

    /**
     * OIDC Registration §2 gives this member none of the tolerance ClientUri keeps for a development
     * stack: it is "https" on a loopback host as anywhere else
     * (module `oidcc-3rd_party-init-login-nohttps`).
     */
    #[Test]
    #[DataProvider('provideHostsPlainHttpNeverReaches')]
    public function itRejectsPlainHttpWhateverTheHost(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('must use HTTPS, on a loopback host as anywhere else');

        // When
        new InitiateLoginUri($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHostsPlainHttpNeverReaches(): iterable
    {
        yield 'the loopback name of the conformance suite' => ['http://localhost:8443/test/a/heidi/initiate-login'];
        yield 'a name under localhost' => ['http://rp.localhost/start'];
        yield 'the IPv4 loopback literal' => ['http://127.0.0.1:8000/start'];
        yield 'the IPv6 loopback literal' => ['http://[::1]:8000/start'];
        yield 'a name' => ['http://rp.example/start'];
        yield 'a scheme in capitals (RFC 3986 §3.1, compared without regard to case)' => ['HTTP://rp.example/start'];
    }

    /**
     * What may be registered at all is the rule of ClientUri, which this URI is one use of: what it
     * refuses of every client URI is refused here too, and this class adds one rule to it.
     */
    #[Test]
    public function itIsAUriAClientMayRegister(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('fragment');

        // When
        new InitiateLoginUri('https://rp.example/start#frag');
    }

    /**
     * A value that carries no scheme at all is not a URI a client may register, and the rule of every one of
     * them answers for it: this class refuses a scheme, never the absence of one.
     */
    #[Test]
    public function aValueWithNoSchemeIsLeftToTheRuleOfEveryClientUri(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not an absolute URI');

        // When
        new InitiateLoginUri('/start');
    }

    /**
     * OIDC Core §4: the query the client registered is kept and the parameters are added to it.
     */
    #[Test]
    public function itKeepsTheRegisteredQueryAndAddsTheParameters(): void
    {
        // Given
        $uri = new InitiateLoginUri('https://rp.example/start?app=1');

        // When
        $location = $uri->withParameters(['iss' => 'https://op.example']);

        // Then
        static::assertSame('https://rp.example/start?app=1&iss=https%3A%2F%2Fop.example', $location);
    }
}
