<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What a token request asks its access token to carry beyond its scopes (RFC 9396 §7), read once for every
 * grant that spends an authorization: a subset of what was agreed to, or nothing.
 */
final class RequestedAuthorizationDetailsTest extends TestCase
{
    private RequestedAuthorizationDetails $requested;

    protected function setUp(): void
    {
        $this->requested = new RequestedAuthorizationDetails(AuthorizationDetailTypes::served());
    }

    /**
     * RFC 9396 §7: a request that asks for nothing narrows nothing, and the response carries what the
     * authorization carries.
     */
    #[Test]
    public function aRequestThatAsksForNoDetailNarrowsNothing(): void
    {
        // When / Then
        static::assertNull($this->requested->of(RequestParameters::of([]), AuthorizationDetailTypes::details()));
    }

    #[Test]
    public function aRequestThatAsksForASubsetIsServedThatSubset(): void
    {
        // Given
        $granted = new AuthorizationDetails([
            AuthorizationDetailTypes::detail('acct-4711'),
            AuthorizationDetailTypes::detail('acct-0815'),
        ]);

        // When
        $narrowed = $this->requested->of(self::request(AuthorizationDetailTypes::parameter('acct-0815')), $granted);

        // Then
        static::assertTrue($narrowed?->equals(AuthorizationDetailTypes::details('acct-0815')));
    }

    /**
     * RFC 9396 §7: narrowing never widens, a token request being no second chance to ask.
     */
    #[Test]
    public function aRequestThatAsksForADetailTheAuthorizationDoesNotCarryIsRefused(): void
    {
        // Given
        $granted = AuthorizationDetailTypes::details('acct-4711');

        // Then
        $this->expectException(OAuth2Exception::class);
        $this->expectExceptionMessageIs('invalid_authorization_details: The requested authorization detail is not among the details of this authorization (RFC 9396 section 7).');

        // When
        $this->requested->of(self::request(AuthorizationDetailTypes::parameter('acct-0815')), $granted);
    }

    /**
     * A grant nobody agreed to a detail for carries none, so there is nothing to narrow and the request is
     * refused rather than served what it asked for.
     */
    #[Test]
    public function aRequestThatAsksForADetailOfAnAuthorizationCarryingNoneIsRefused(): void
    {
        // Then
        $this->expectException(OAuth2Exception::class);
        $this->expectExceptionMessageIs('invalid_authorization_details: The requested authorization detail is not among the details of this authorization (RFC 9396 section 7).');

        // When
        $this->requested->of(self::request(AuthorizationDetailTypes::parameter()), null);
    }

    /**
     * RFC 9396 §5: read the one way the authorization endpoint reads it, refused the one way it refuses it,
     * without a redirect, this endpoint answering in JSON.
     */
    #[Test]
    public function aParameterThatIsNotAnAuthorizationDetailsIsRefused(): void
    {
        // Then
        $this->expectException(OAuth2Exception::class);
        $this->expectExceptionMessageIsOrContains('invalid_authorization_details: The authorization_details parameter is a JSON array of objects');

        // When
        $this->requested->of(self::request('[{'), AuthorizationDetailTypes::details());
    }

    /**
     * A refusal of the token endpoint is never redirected: it answers in JSON.
     */
    #[Test]
    public function itsRefusalIsNotRedirectable(): void
    {
        // When
        try {
            $this->requested->of(self::request(AuthorizationDetailTypes::parameter()), null);
            static::fail('The request should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertFalse($exception->redirectable);
        }
    }

    private static function request(string $authorizationDetails): RequestParameters
    {
        return RequestParameters::of([
            'authorization_details' => $authorizationDetails,
        ]);
    }
}
