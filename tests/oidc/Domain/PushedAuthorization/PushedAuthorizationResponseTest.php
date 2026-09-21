<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\PushedAuthorization;

use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationResponse;
use Heidi\Oidc\Domain\PushedAuthorization\RequestUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PushedAuthorizationResponseTest extends TestCase
{
    /**
     * RFC 9126 §2.2: the two members of the answer, and no other.
     */
    #[Test]
    public function itCarriesTheReferenceAndItsLifetime(): void
    {
        // Given
        $requestUri = RequestUri::generate();

        // When
        $parameters = new PushedAuthorizationResponse($requestUri, 60)
            ->parameters();

        // Then
        static::assertSame([
            'request_uri' => $requestUri->value,
            'expires_in' => 60,
        ], $parameters);
    }

    /**
     * RFC 9126 §2.2: one second is a lifetime, and the smallest the endpoint ever answers.
     */
    #[Test]
    public function theSmallestLifetimeItAnswersIsOneSecond(): void
    {
        // When / Then
        static::assertSame(1, new PushedAuthorizationResponse(RequestUri::generate(), 1)->expiresIn);
    }

    /**
     * RFC 9126 §2.2: "a positive integer".
     */
    #[Test]
    #[DataProvider('provideLifetimesThatAreNotPositive')]
    public function itRefusesALifetimeThatIsNotPositive(int $expiresIn): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A request URI is answered with the seconds it still lives, at least one (RFC 9126 section 2.2).');

        // When
        new PushedAuthorizationResponse(RequestUri::generate(), $expiresIn);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideLifetimesThatAreNotPositive(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }
}
