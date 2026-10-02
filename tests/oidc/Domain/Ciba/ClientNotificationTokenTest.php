<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Ciba;

use Beffroi\Oidc\Domain\Ciba\ClientNotificationToken;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * CIBA Core §7.1: what a client sends so that it recognises the call this provider makes back, and what
 * this provider therefore has to be able to present in an Authorization header (RFC 6750 §2.1).
 */
final class ClientNotificationTokenTest extends TestCase
{
    /**
     * §7.1: a token of at least 128 bits of entropy, which a header can carry as it is.
     */
    #[Test]
    #[DataProvider('provideAcceptedTokens')]
    public function itKeepsABearerTokenAsItWasSent(string $token): void
    {
        // When / Then
        static::assertSame($token, new ClientNotificationToken($token)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedTokens(): iterable
    {
        yield 'base64url of 128 bits' => ['8d1d7ac0e2f34b5c9d0e1f2a3b'];
        yield 'the shortest one that carries them' => [str_repeat('a', 22)];
        yield 'padded base64' => [str_repeat('a', 30) . '=='];
        yield 'as long as it may be' => [str_repeat('b', 1024)];
    }

    /**
     * §7.1: a token this provider could not present back, or one too short to carry what the
     * specification asks of it, is refused where it arrives.
     */
    #[Test]
    #[DataProvider('provideRefusedTokens')]
    public function itRefusesWhatItCouldNotPresentBack(string $token, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new ClientNotificationToken($token);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusedTokens(): iterable
    {
        yield 'empty' => ['', 'A client notification token is between 22 and 1024 characters'];
        yield 'too short for 128 bits' => [str_repeat('a', 21), 'A client notification token is between 22 and 1024 characters'];
        yield 'longer than the specification allows' => [str_repeat('a', 1025), 'A client notification token is between 22 and 1024 characters'];
        yield 'a space' => [str_repeat('a', 11) . ' ' . str_repeat('a', 11), 'A client notification token is a bearer token'];
        yield 'a character a header cannot carry' => [str_repeat('a', 21) . '"', 'A client notification token is a bearer token'];
        yield 'padding in the middle' => [str_repeat('a', 11) . '=' . str_repeat('a', 11), 'A client notification token is a bearer token'];
    }
}
