<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\PushedAuthorization;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationResponse;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PushedAuthorizationResponseTest extends TestCase
{
    /**
     * RFC 9126 §2.2
     */
    #[Test]
    public function itCarriesTheReferenceAndItsLifetime(): void
    {
        // Given
        $requestUri = RequestUri::of(Secrets::draw());

        // When
        $parameters = new PushedAuthorizationResponse($requestUri, 60)->parameters();

        // Then
        static::assertSame(
            [
                'request_uri' => $requestUri->value,
                'expires_in' => 60,
            ],
            $parameters,
        );
    }

    /**
     * RFC 9126 §2.2
     */
    #[Test]
    public function theSmallestLifetimeItAnswersIsOneSecond(): void
    {
        // When / Then
        static::assertSame(1, new PushedAuthorizationResponse(RequestUri::of(Secrets::draw()), 1)->expiresIn);
    }

    /**
     * RFC 9126 §2.2
     */
    #[Test]
    #[DataProvider('provideLifetimesThatAreNotPositive')]
    public function itRefusesALifetimeThatIsNotPositive(int $expiresIn): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A request URI is answered with the seconds it still lives, at least one (RFC 9126 section 2.2).');

        // When
        new PushedAuthorizationResponse(RequestUri::of(Secrets::draw()), $expiresIn);
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
