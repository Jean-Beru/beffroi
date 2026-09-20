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
     * RFC 6749 §4.1.2: code and state; RFC 9207 §2: iss in every authorization response. How they reach
     * the client is the response mode's business, not the response's (Multiple Response Type Encoding
     * Practices §2.1).
     */
    #[Test]
    public function itCarriesTheCodeTheStateAndTheIssuer(): void
    {
        // When
        $response = new AuthorizationResponse(new Issuer('https://id.acme.example'), new RedirectUri('https://spa.example/callback?app=1'), 'af0ifjsldkj', 'SplxlOBeZQQYbYS6WxSbIA');

        // Then
        static::assertSame([
            'code' => 'SplxlOBeZQQYbYS6WxSbIA',
            'state' => 'af0ifjsldkj',
            'iss' => 'https://id.acme.example',
        ], $response->parameters());
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
