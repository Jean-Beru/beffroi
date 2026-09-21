<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use DateInterval;
use Heidi\Core\Application\Authentication\DecoyHash;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientAuthenticationMethods;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Application\Client\Method\ClientSecretBasic;
use Heidi\Oidc\Application\Client\Method\ClientSecretJwt;
use Heidi\Oidc\Application\Client\Method\ClientSecretPost;
use Heidi\Oidc\Application\Client\Method\NoAuthentication;
use Heidi\Oidc\Application\Client\Method\PrivateKeyJwt;
use Heidi\Oidc\Application\Client\Method\SelfSignedTlsClientAuth;
use Heidi\Oidc\Application\Client\Method\TlsClientAuth;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientAssertionReplayGuard;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientJwksCache;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryClientAssertionKeyVerifier;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryClientAssertionReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryClientAssertionSecretVerifier;
use Heidi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Heidi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Heidi\Oidc\Port\ClientJwksFetcherInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;

/**
 * The client authentication methods, wired as the bundle wires them. A method that verifies a secret
 * gets the fake hasher of the core unless the test brings its own; a method that verifies an assertion
 * gets the real bridge, because what it verifies is a real signature.
 */
final class Methods
{
    public static function clientSecretBasic(?PasswordHasherInterface $hasher = null, ?DecoyHash $decoy = null): ClientSecretBasic
    {
        $hasher ??= new FakePasswordHasher();

        return new ClientSecretBasic($hasher, $decoy ?? new DecoyHash($hasher));
    }

    public static function clientSecretPost(?PasswordHasherInterface $hasher = null, ?DecoyHash $decoy = null): ClientSecretPost
    {
        $hasher ??= new FakePasswordHasher();

        return new ClientSecretPost($hasher, $decoy ?? new DecoyHash($hasher));
    }

    public static function none(): NoAuthentication
    {
        return new NoAuthentication();
    }

    public static function privateKeyJwt(?ClientKeySetProvider $keys = null, ?ClientAssertionValidator $claims = null): PrivateKeyJwt
    {
        return new PrivateKeyJwt(
            new JwtLibraryClientAssertionReader(),
            new JwtLibraryClientAssertionKeyVerifier(Algorithms::all()->manager()),
            $keys ?? self::keySetProvider(),
            $claims ?? self::assertionValidator(),
            Algorithms::all(),
        );
    }

    public static function clientSecretJwt(?ClientAssertionValidator $claims = null): ClientSecretJwt
    {
        return new ClientSecretJwt(
            new JwtLibraryClientAssertionReader(),
            new JwtLibraryClientAssertionSecretVerifier(new AlgorithmManager([new HS256()])),
            $claims ?? self::assertionValidator(),
        );
    }

    public static function tlsClientAuth(): TlsClientAuth
    {
        return new TlsClientAuth(new PkiFrameworkCertificateReader());
    }

    public static function selfSignedTlsClientAuth(?ClientKeySetProvider $keys = null): SelfSignedTlsClientAuth
    {
        return new SelfSignedTlsClientAuth($keys ?? self::keySetProvider());
    }

    public static function keySetProvider(?ClientJwksFetcherInterface $fetcher = null, ?ClockInterface $clock = null, ?DateInterval $cooldown = null): ClientKeySetProvider
    {
        return new ClientKeySetProvider(
            $fetcher ?? new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]),
            new InMemoryClientJwksCache(),
            $clock ?? new MockClock('2026-09-15T12:00:00+00:00'),
            $cooldown ?? new DateInterval('PT300S'),
        );
    }

    public static function assertionValidator(?ClientAssertionReplayGuardInterface $replays = null): ClientAssertionValidator
    {
        return new ClientAssertionValidator($replays ?? new InMemoryClientAssertionReplayGuard(), new DateInterval('PT300S'), new DateInterval('PT30S'));
    }

    /**
     * The seven methods in the order the bundle wires them, sharing one decoy as the container shares it.
     */
    public static function all(?PasswordHasherInterface $hasher = null, ?ClientKeySetProvider $keys = null, ?ClientAssertionValidator $claims = null): ClientAuthenticationMethods
    {
        $hasher ??= new FakePasswordHasher();
        $decoy = new DecoyHash($hasher);
        $claims ??= self::assertionValidator();

        return new ClientAuthenticationMethods([
            self::clientSecretBasic($hasher, $decoy),
            self::clientSecretPost($hasher, $decoy),
            self::privateKeyJwt($keys, $claims),
            self::clientSecretJwt($claims),
            self::tlsClientAuth(),
            self::selfSignedTlsClientAuth($keys),
            self::none(),
        ]);
    }
}
