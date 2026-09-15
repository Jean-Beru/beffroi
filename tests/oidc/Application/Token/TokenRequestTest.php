<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Exception\InvalidRequestException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6749 §3.1, applied to the token endpoint (§3.2): a parameter without a value is omitted, a
 * repeated or nested one is refused rather than reduced to one.
 */
final class TokenRequestTest extends TestCase
{
    private TokenRequest $request;

    protected function setUp(): void
    {
        $this->request = new TokenRequest([
            'grant_type' => 'authorization_code',
            'code' => '',
            'scope' => ['openid', 'profile'],
        ]);
    }

    #[Test]
    public function itReadsAParameterWithAValue(): void
    {
        // When / Then
        static::assertSame('authorization_code', $this->request->required('grant_type'));
        static::assertSame('authorization_code', $this->request->optional('grant_type'));
    }

    #[Test]
    #[DataProvider('provideOmittedParameters')]
    public function anOptionalParameterWithoutAValueIsNull(string $name): void
    {
        // When / Then
        static::assertNull($this->request->optional($name));
    }

    #[Test]
    #[DataProvider('provideOmittedParameters')]
    public function aRequiredParameterWithoutAValueIsMissing(string $name): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The ' . $name . ' parameter is missing.');

        // When
        $this->request->required($name);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOmittedParameters(): iterable
    {
        yield 'empty' => ['code'];
        yield 'absent' => ['redirect_uri'];
    }

    #[Test]
    public function aRepeatedRequiredParameterIsRefused(): void
    {
        // When
        try {
            $this->request->required('scope');
            static::fail('A repeated parameter is refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertSame('The scope parameter must be a single string.', $exception->errorDescription);
            static::assertFalse($exception->redirectable);
        }
    }

    #[Test]
    public function aRepeatedOptionalParameterIsRefused(): void
    {
        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessage('The scope parameter must be a single string.');

        // When
        $this->request->optional('scope');
    }
}
