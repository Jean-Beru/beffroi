<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Authorization\AuthorizationResponse;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthorizationResponseTest extends TestCase
{
    /**
     * RFC 6749 §4.1.2, RFC 9207 §2
     */
    #[Test]
    public function itCarriesTheCodeTheStateAndTheIssuer(): void
    {
        // When
        $response = new AuthorizationResponse(
            new Issuer('https://id.acme.example'),
            new RedirectUri('https://spa.example/callback?app=1'),
            'af0ifjsldkj',
            'SplxlOBeZQQYbYS6WxSbIA',
        );

        // Then
        static::assertSame(
            [
                'code' => 'SplxlOBeZQQYbYS6WxSbIA',
                'state' => 'af0ifjsldkj',
                'iss' => 'https://id.acme.example',
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 6749 §4.1.2
     */
    #[Test]
    public function itOmitsTheStateWhenTheRequestHadNone(): void
    {
        // When
        $response = new AuthorizationResponse(
            new Issuer('https://id.acme.example'),
            new RedirectUri('https://spa.example/callback'),
            null,
            'SplxlOBeZQQYbYS6WxSbIA',
        );

        // Then
        static::assertSame(
            [
                'code' => 'SplxlOBeZQQYbYS6WxSbIA',
                'iss' => 'https://id.acme.example',
            ],
            $response->parameters(),
        );
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
