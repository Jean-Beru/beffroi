<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Port\AccessTokenVerifierInterface;
use SensitiveParameter;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * The other side of the invented shape (issue #239): it answers to the name its issuer writes, so the
 * wiring holds together, and it recognises what that issuer wrote and nothing else.
 */
final readonly class InventedAccessTokenVerifier implements AccessTokenVerifierInterface
{
    public function __construct(
        private OpaqueAccessTokenVerifier $verifier,
    ) {
    }

    public function name(): string
    {
        return InventedAccessTokenIssuer::NAME;
    }

    public function recognises(#[SensitiveParameter] string $accessToken): bool
    {
        return str_starts_with($accessToken, InventedAccessTokenIssuer::PREFIX);
    }

    public function expiresOnItsOwn(): bool
    {
        return false;
    }

    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        return $this->verifier->verify($tenant, substr($accessToken, strlen(InventedAccessTokenIssuer::PREFIX)), $now);
    }
}
