<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Token\PresentedAccessToken;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PresentedAccessTokenTest extends TestCase
{
    private const string JWS = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmFjbWUuZXhhbXBsZSJ9.c2ln';

    /**
     * RFC 7638 §3.1: the base64url of a SHA-256, whatever it is the thumbprint of.
     */
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    /**
     * RFC 9449 §7.1: a token is presented the way it was issued. One bound to a key is sent under the
     * "DPoP" scheme, one bound to nothing or to a certificate as a bearer token (RFC 8705 §3, which
     * changes nothing to how a client sends it).
     */
    #[Test]
    #[DataProvider('providePresentations')]
    public function aTokenIsPresentedUnderTheSchemeItsBindingCallsFor(string $scheme, ?string $member, bool $honoured): void
    {
        // Given
        $presented = new PresentedAccessToken($scheme, self::JWS);
        $confirmation = match ($member) {
            KeyConfirmation::MEMBER => new KeyConfirmation(self::THUMBPRINT),
            CertificateConfirmation::MEMBER => new CertificateConfirmation(self::THUMBPRINT),
            default => null,
        };

        // When / Then
        static::assertSame($honoured, $presented->isPresentedAs($confirmation));
    }

    /**
     * @return iterable<string, array{string, string|null, bool}>
     */
    public static function providePresentations(): iterable
    {
        yield 'a bearer token as a bearer token' => [TokenResponse::BEARER, null, true];
        yield 'a bearer token under DPoP' => [KeyConfirmation::SCHEME, null, false];
        yield 'a key-bound token under DPoP' => [KeyConfirmation::SCHEME, KeyConfirmation::MEMBER, true];
        yield 'a key-bound token as a bearer token' => [TokenResponse::BEARER, KeyConfirmation::MEMBER, false];
        yield 'a certificate-bound token as a bearer token' => [TokenResponse::BEARER, CertificateConfirmation::MEMBER, true];
        yield 'a certificate-bound token under DPoP' => [KeyConfirmation::SCHEME, CertificateConfirmation::MEMBER, false];
    }
}
