<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Heidi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Heidi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;

/**
 * The two shapes this provider writes an access token in, wired as the bundle wires them. A test names
 * only what its shape needs and takes the other as a deployment has it.
 */
final class AccessTokenShapes
{
    public static function verifier(
        JwsVerifierInterface $jws,
        ClientRepositoryInterface $clients,
        ?AccessTokenRepositoryInterface $storedTokens = null,
        ?SubjectIdentifierResolverInterface $subjects = null,
    ): AccessTokenVerifier {
        return new AccessTokenVerifier([
            new JwtAccessTokenVerifier($jws, $clients),
            new OpaqueAccessTokenVerifier($storedTokens ?? new InMemoryAccessTokenRepository(), $subjects ?? new PublicSubjectIdentifierResolver()),
        ]);
    }
}
