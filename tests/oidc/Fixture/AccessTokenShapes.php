<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Port\JwsVerifierInterface;
use Beffroi\Oidc\Application\Token\AccessTokenVerifier;
use Beffroi\Oidc\Application\Token\JwtAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\OpaqueAccessTokenVerifier;
use Beffroi\Oidc\Application\Token\SealedPerson;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

final class AccessTokenShapes
{
    public static function verifier(
        JwsVerifierInterface $jws,
        ClientRepositoryInterface $clients,
        ?AccessTokenRepositoryInterface $storedTokens = null,
        ?SubjectIdentifierResolverInterface $subjects = null,
        ?SealedPerson $persons = null,
    ): AccessTokenVerifier {
        return new AccessTokenVerifier([
            new JwtAccessTokenVerifier($jws, $clients, Bindings::wired(), AuthorizationDetailTypes::served(), $persons ?? Subjects::sealedPerson()),
            new OpaqueAccessTokenVerifier($storedTokens ?? new InMemoryAccessTokenRepository(), $subjects ?? Subjects::publicKind()),
        ], Shapes::served());
    }
}
