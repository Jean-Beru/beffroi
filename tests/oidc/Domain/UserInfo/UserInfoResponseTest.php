<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\UserInfo;

use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Tests\Fixture\Bindings;
use Beffroi\Oidc\Domain\UserInfo\UserInfoErrorResponse;
use Beffroi\Oidc\Domain\UserInfo\UserInfoResponse;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Exception\InsufficientScopeException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\TokenBindingNotProvenException;
use Beffroi\Oidc\Exception\UseDpopNonceException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

final class UserInfoResponseTest extends TestCase
{
    /**
     * OIDC Core §5.3.2: "sub" first, then the claims as JSON values of their kind; a "sub" a provider
     * would return is not the response's.
     */
    #[Test]
    public function itWritesSubFirstThenTheClaimsAsTheyAre(): void
    {
        // When
        $response = UserInfoResponse::json('alice-subject', [
            'email' => 'alice@acme.example',
            'sub' => 'someone-else',
            'email_verified' => true,
            'updated_at' => 1789466400,
            'address' => [
                'country' => 'FR',
            ],
        ]);

        // Then
        static::assertSame('alice-subject', $response->subject);
        static::assertSame(
            [
                'sub' => 'alice-subject',
                'email' => 'alice@acme.example',
                'email_verified' => true,
                'updated_at' => 1789466400,
                'address' => [
                    'country' => 'FR',
                ],
            ],
            $response->claims,
        );
        static::assertSame(
            '{"sub":"alice-subject","email":"alice@acme.example","email_verified":true,"updated_at":1789466400,"address":{"country":"FR"}}',
            $response->body,
        );
        static::assertSame('application/json', $response->contentType);
    }

    #[Test]
    public function aResponseWithoutClaimsCarriesSubAlone(): void
    {
        // When / Then
        static::assertSame('{"sub":"alice-subject"}', UserInfoResponse::json('alice-subject', [])->body);
    }

    #[Test]
    public function itRefusesAnEmptySubject(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        UserInfoResponse::json('', []);
    }

    /**
     * RFC 6750 §3: the challenge carries "error" and "error_description"; the status is the exception's;
     * the body repeats the error.
     */
    #[Test]
    public function anInvalidTokenIsA401WithTheErrorInTheChallenge(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(
            new InvalidTokenException('The access token expired.'),
            Bindings::schemes(),
            Bindings::challengeParameters(),
        );

        // Then
        static::assertSame(401, $response->statusCode);
        static::assertSame('invalid_token', $response->error);
        static::assertSame('The access token expired.', $response->errorDescription);
        static::assertNull($response->scope);
        static::assertSame('Bearer error="invalid_token", error_description="The access token expired."', $response->challenge());
        static::assertSame(
            [
                'error' => 'invalid_token',
                'error_description' => 'The access token expired.',
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 9449 §7.2: a token presented under the DPoP scheme is refused in the challenge of that scheme,
     * which names the algorithms a proof may be signed with (§7.1).
     */
    #[Test]
    public function aTokenRefusedAsInvalidIsChallengedUnderTheSchemeItWasPresentedUnder(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(
            InvalidTokenException::expired()->presentedUnder(KeyConfirmation::SCHEME),
            Bindings::schemes(),
            Bindings::challengeParameters(),
        );

        // Then
        static::assertSame(401, $response->statusCode);
        static::assertSame(
            'DPoP error="invalid_token", error_description="The access token expired.", algs="RS256 PS256 ES256 EdDSA"',
            $response->challenge(),
        );
    }

    /**
     * RFC 9449 §7.1: every challenge under the DPoP scheme names the algorithms a proof may be signed
     * with, after what the refusal says.
     */
    #[Test]
    #[DataProvider('provideRefusalsUnderDpop')]
    public function everyChallengeUnderDpopNamesTheAlgorithmsAProofMaySignWith(OAuth2Exception $refusal): void
    {
        // When
        $response = UserInfoErrorResponse::fromException($refusal, Bindings::schemes(), Bindings::challengeParameters());

        // Then
        static::assertSame(
            sprintf('DPoP error="%s", error_description="%s", algs="RS256 PS256 ES256 EdDSA"', $refusal->error, $refusal->errorDescription),
            $response->challenge(),
        );
    }

    /**
     * @return iterable<string, array{OAuth2Exception}>
     */
    public static function provideRefusalsUnderDpop(): iterable
    {
        yield 'a proof that does not verify' => [new InvalidDpopProofException('The DPoP proof is not a readable JWT (RFC 9449 section 4.2).')];
        yield 'a proof without the nonce asked for' => [new UseDpopNonceException(
            'the-nonce',
            'The DPoP proof does not carry the nonce this provider issued (RFC 9449 section 8).',
        )];
        yield 'a key binding not proven' => [new TokenBindingNotProvenException(
            'The access token is bound to a key and was presented as a bearer token (RFC 9449 section 7.1).',
            new KeyConfirmation(str_repeat('A', 43)),
        )];
        yield 'a token addressed elsewhere' => [InvalidTokenException::addressedElsewhere(KeyConfirmation::SCHEME)];
    }

    /**
     * RFC 6750 §3: nothing is cached.
     */
    #[Test]
    public function anErrorIsNotCached(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(
            new InvalidTokenException('The access token expired.'),
            Bindings::schemes(),
            Bindings::challengeParameters(),
        );

        // Then
        static::assertSame(
            [
                'WWW-Authenticate' => 'Bearer error="invalid_token", error_description="The access token expired."',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ],
            $response->headers(),
        );
    }

    /**
     * RFC 6750 §3.1: invalid_request is a 400, through the same challenge.
     */
    #[Test]
    public function anInvalidRequestIsA400(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(
            new InvalidRequestException('The access token is sent by more than one method.'),
            Bindings::schemes(),
            Bindings::challengeParameters(),
        );

        // Then
        static::assertSame(400, $response->statusCode);
        static::assertSame('Bearer error="invalid_request", error_description="The access token is sent by more than one method."', $response->challenge());
    }

    /**
     * RFC 6750 §3: insufficient_scope is a 403 and the challenge names the scopes that would have done.
     */
    #[Test]
    public function anInsufficientScopeIsA403NamingTheScopes(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(
            new InsufficientScopeException(
                'The token opens nothing here.',
                new Scopes([
                    Scope::openid(),
                    new Scope('profile'),
                ]),
                TokenResponse::BEARER,
            ),
            Bindings::schemes(),
            Bindings::challengeParameters(),
        );

        // Then
        static::assertSame(403, $response->statusCode);
        static::assertSame('insufficient_scope', $response->error);
        static::assertSame('openid profile', $response->scope);
        static::assertSame(
            'Bearer error="insufficient_scope", error_description="The token opens nothing here.", scope="openid profile"',
            $response->challenge(),
        );
        static::assertSame(
            [
                'error' => 'insufficient_scope',
                'error_description' => 'The token opens nothing here.',
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 9449 §7.2: a token honoured here and not enough is a 403 under the scheme it was presented
     * under, the challenge naming the scope that would have done (RFC 6750 §3) and, under "DPoP", the
     * algorithms a proof may be signed with (RFC 9449 §7.1).
     */
    #[Test]
    public function anInsufficientScopeIsChallengedUnderTheSchemeTheTokenWasPresentedUnder(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(
            new InsufficientScopeException('The token opens nothing here.', new Scopes([Scope::openid()]), KeyConfirmation::SCHEME),
            Bindings::schemes(),
            Bindings::challengeParameters(),
        );

        // Then
        static::assertSame(403, $response->statusCode);
        static::assertSame(
            'DPoP error="insufficient_scope", error_description="The token opens nothing here.", scope="openid", algs="RS256 PS256 ES256 EdDSA"',
            $response->challenge(),
        );
    }

    /**
     * RFC 6750 §3.1: a request without any token gets the bare challenge, no error code, no body.
     */
    #[Test]
    public function aRequestWithoutTokenGetsTheBareChallenge(): void
    {
        // When
        $response = UserInfoErrorResponse::fromException(new MissingBearerTokenException(), Bindings::schemes(), Bindings::challengeParameters());

        // Then
        static::assertSame(401, $response->statusCode);
        static::assertNull($response->error);
        static::assertNull($response->errorDescription);
        static::assertNull($response->scope);
        static::assertSame('Bearer, DPoP algs="RS256 PS256 ES256 EdDSA"', $response->challenge());
        static::assertSame(
            [
                'WWW-Authenticate' => 'Bearer, DPoP algs="RS256 PS256 ES256 EdDSA"',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ],
            $response->headers(),
        );
        static::assertSame([], $response->parameters());
    }

    /**
     * The description is optional in the challenge (RFC 6750 §3) and so in the body.
     */
    #[Test]
    public function theDescriptionIsOptional(): void
    {
        // When
        $response = new UserInfoErrorResponse(401, 'invalid_token', null);

        // Then
        static::assertSame('Bearer error="invalid_token"', $response->challenge());
        static::assertSame(
            [
                'error' => 'invalid_token',
            ],
            $response->parameters(),
        );
    }
}
