<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Authorization\AuthorizationResponse;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthorizationResponseTest extends TestCase
{
    /**
     * RFC 6749 §4.1.2: code and state in the query component of the redirect URI; RFC 9207 §2: iss in
     * every authorization response.
     */
    #[Test]
    public function itRedirectsWithCodeStateAndIssuer(): void
    {
        // When
        $response = new AuthorizationResponse(new Issuer('https://id.acme.example'), new RedirectUri('https://spa.example/callback?app=1'), 'af0ifjsldkj', 'SplxlOBeZQQYbYS6WxSbIA');

        // Then
        static::assertSame([
            'code' => 'SplxlOBeZQQYbYS6WxSbIA',
            'state' => 'af0ifjsldkj',
            'iss' => 'https://id.acme.example',
        ], $response->parameters());
        static::assertSame('https://spa.example/callback?app=1&code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj&iss=https%3A%2F%2Fid.acme.example', $response->toUri());
    }

    /**
     * RFC 6749 §4.1.2: state is present in the response only when it was in the request.
     */
    #[Test]
    public function itOmitsTheStateWhenTheRequestHadNone(): void
    {
        // When
        $response = new AuthorizationResponse(new Issuer('https://id.acme.example'), new RedirectUri('https://spa.example/callback'), null, 'SplxlOBeZQQYbYS6WxSbIA');

        // Then
        static::assertSame([
            'code' => 'SplxlOBeZQQYbYS6WxSbIA',
            'iss' => 'https://id.acme.example',
        ], $response->parameters());
        static::assertSame('https://spa.example/callback?code=SplxlOBeZQQYbYS6WxSbIA&iss=https%3A%2F%2Fid.acme.example', $response->toUri());
    }

    #[Test]
    public function itRefusesAnEmptyCode(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthorizationResponse(new Issuer('https://id.acme.example'), new RedirectUri('https://spa.example/callback'), null, '');
    }
}
