<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Exception\InvalidRequestException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class TokenRequestTest extends TestCase
{
    /**
     * RFC 6749 §3.1, applied to the token endpoint (§3.2): a parameter without a value is omitted, a
     * repeated or nested one is refused rather than reduced to one.
     */
    #[Test]
    public function itReadsParametersWithTheRulesOfRfc6749Section31(): void
    {
        $request = new TokenRequest([
            'grant_type' => 'authorization_code',
            'code' => '',
            'scope' => ['openid', 'profile'],
        ]);

        static::assertSame('authorization_code', $request->required('grant_type'));
        static::assertSame('authorization_code', $request->optional('grant_type'));
        static::assertNull($request->optional('code'));
        static::assertNull($request->optional('redirect_uri'));

        try {
            $request->required('code');
            static::fail('An empty parameter is missing.');
        } catch (InvalidRequestException $exception) {
            static::assertSame('The code parameter is missing.', $exception->errorDescription);
        }
        try {
            $request->required('redirect_uri');
            static::fail('An absent parameter is missing.');
        } catch (InvalidRequestException $exception) {
            static::assertSame('The redirect_uri parameter is missing.', $exception->errorDescription);
        }
        try {
            $request->required('scope');
            static::fail('A repeated parameter is refused.');
        } catch (InvalidRequestException $exception) {
            static::assertSame('The scope parameter must be a single string.', $exception->errorDescription);
            static::assertFalse($exception->redirectable);
        }
        try {
            $request->optional('scope');
            static::fail('A repeated parameter is refused.');
        } catch (InvalidRequestException $exception) {
            static::assertSame('The scope parameter must be a single string.', $exception->errorDescription);
        }
    }
}
