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
     * RFC 7638 §3.1
     */
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    /**
     * RFC 9449 §7.1, RFC 8705 §3
     *
     * @param non-empty-string $scheme
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
     * @return iterable<string, array{non-empty-string, string|null, bool}>
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
