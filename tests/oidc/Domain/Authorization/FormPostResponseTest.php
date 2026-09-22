<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use Heidi\Oidc\Domain\Authorization\FormPostResponse;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class FormPostResponseTest extends TestCase
{
    /**
     * OAuth 2.0 Form Post Response Mode §2: the parameters of the answer and where the form posts them.
     */
    #[Test]
    public function itCarriesTheParametersAndTheRedirectUriOfTheAnswer(): void
    {
        // When
        $response = new FormPostResponse(new RedirectUri('https://rp.example/cb'), [
            'code' => 'SplxlOBeZQQYbYS6WxSbIA',
            'state' => 'af0ifjsldkj',
            'iss' => 'https://id.acme.example',
        ]);

        // Then
        static::assertSame('https://rp.example/cb', $response->redirectUri->value);
        static::assertSame(
            [
                'code' => 'SplxlOBeZQQYbYS6WxSbIA',
                'state' => 'af0ifjsldkj',
                'iss' => 'https://id.acme.example',
            ],
            $response->parameters,
        );
    }

    /**
     * CSP Level 3 §6.6.2.2: the base64 of the SHA-256 of the text of the script element, so that the page
     * allows that script and no other. The value is written out: a change to the script that forgot the
     * policy would leave the page unable to run its own script, and this test is what says so.
     */
    #[Test]
    public function theHashIsTheOneOfTheScriptThePageCarries(): void
    {
        // When
        $hash = self::response()->scriptHash();

        // Then
        static::assertSame('sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ=', $hash);
    }

    /**
     * CSP Level 3 §6.1: nothing loads, nothing frames, no base URI, the one script is named by its hash
     * and the form posts to the origin of the redirect URI and nowhere else.
     */
    #[Test]
    public function thePolicyAllowsTheScriptByHashAndNothingElse(): void
    {
        // When
        $policy = self::response()->contentSecurityPolicy();

        // Then
        static::assertSame(
            "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; form-action https://rp.example; base-uri 'none'; frame-ancestors 'none'",
            $policy,
        );
    }

    /**
     * The policy names an origin, never a path: a redirect URI with a port or a query keeps the scheme,
     * the host and the port alone (RFC 6454 §3.2).
     */
    #[Test]
    #[DataProvider('provideRedirectUris')]
    public function thePolicyNamesTheOriginOfTheRedirectUri(string $redirectUri, string $origin): void
    {
        // When
        $policy = new FormPostResponse(new RedirectUri($redirectUri), [
            'code' => 'SplxlOBeZQQYbYS6WxSbIA',
        ])->contentSecurityPolicy();

        // Then
        static::assertStringContainsString('form-action ' . $origin . ';', $policy);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRedirectUris(): iterable
    {
        yield 'a path' => ['https://rp.example/login/check', 'https://rp.example'];
        yield 'a port' => ['https://rp.example:8443/cb', 'https://rp.example:8443'];
        yield 'a registered query' => ['https://rp.example/cb?app=1', 'https://rp.example'];
        yield 'a loopback host (RFC 8252 §7.3)' => ['http://127.0.0.1/callback', 'http://127.0.0.1'];
    }

    #[Test]
    public function itRefusesAnAnswerWithoutAParameter(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A form post response carries at least one parameter (Form Post Response Mode section 2).');

        // When
        new FormPostResponse(new RedirectUri('https://rp.example/cb'), []);
    }

    private static function response(): FormPostResponse
    {
        return new FormPostResponse(new RedirectUri('https://rp.example/cb'), [
            'code' => 'SplxlOBeZQQYbYS6WxSbIA',
            'iss' => 'https://id.acme.example',
        ]);
    }
}
