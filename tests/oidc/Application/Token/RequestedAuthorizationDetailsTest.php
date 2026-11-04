<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\RequestedAuthorizationDetails;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9396 §7
 */
final class RequestedAuthorizationDetailsTest extends TestCase
{
    private RequestedAuthorizationDetails $requested;

    protected function setUp(): void
    {
        $this->requested = new RequestedAuthorizationDetails(AuthorizationDetailTypes::served());
    }

    /**
     * RFC 9396 §7
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
     * RFC 9396 §7
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
     * RFC 9396 §5
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
