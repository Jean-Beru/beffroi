<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use DateInterval;
use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Oidc\Application\Client\AcceptedAssertionAudiences;
use Beffroi\Oidc\Application\Client\ClientAssertionValidator;
use Beffroi\Oidc\Application\Client\ClientAuthenticationMethods;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequestParser;
use Beffroi\Oidc\Application\Client\ClientKeySetProvider;
use Beffroi\Oidc\Application\Key\PublishedKeySetProvider;
use Beffroi\Oidc\Application\Client\Method\ClientSecretBasic;
use Beffroi\Oidc\Application\Client\Method\ClientSecretJwt;
use Beffroi\Oidc\Application\Client\Method\ClientSecretPost;
use Beffroi\Oidc\Application\Client\Method\NoAuthentication;
use Beffroi\Oidc\Application\Client\Method\PrivateKeyJwt;
use Beffroi\Oidc\Application\Client\Method\SelfSignedTlsClientAuth;
use Beffroi\Oidc\Application\Client\Method\TlsClientAuth;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientAssertionReplayGuard;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientJwksCache;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryClientAssertionSecretVerifier;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateAuthorities;
use Beffroi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Beffroi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\MockClock;
use Beffroi\Core\Tests\Fixture\FakeMonotonicClock;

final class Methods
{
    public static function clientSecretBasic(?PasswordHasherInterface $hasher = null, ?DecoyHash $decoy = null): ClientSecretBasic
    {
        $hasher ??= new FakePasswordHasher();

        return new ClientSecretBasic($hasher, $decoy ?? new DecoyHash($hasher, new SymfonyUuidGenerator(), new FakeMonotonicClock()));
    }

    public static function clientSecretPost(?PasswordHasherInterface $hasher = null, ?DecoyHash $decoy = null): ClientSecretPost
    {
        $hasher ??= new FakePasswordHasher();

        return new ClientSecretPost($hasher, $decoy ?? new DecoyHash($hasher, new SymfonyUuidGenerator(), new FakeMonotonicClock()));
    }

    public static function none(): NoAuthentication
    {
        return new NoAuthentication();
    }

    public static function privateKeyJwt(?ClientKeySetProvider $keys = null, ?ClientAssertionValidator $claims = null): PrivateKeyJwt
    {
        return new PrivateKeyJwt(
            new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
            $keys ?? self::keySetProvider(),
            $claims ?? self::assertionValidator(),
            Algorithms::all(),
        );
    }

    public static function clientSecretJwt(?ClientAssertionValidator $claims = null): ClientSecretJwt
    {
        return new ClientSecretJwt(
            new JwtLibraryClientAssertionSecretVerifier(new AlgorithmManager([new HS256()])),
            $claims ?? self::assertionValidator(),
        );
    }

    public static function tlsClientAuth(): TlsClientAuth
    {
        return new TlsClientAuth(
            new PkiFrameworkCertificateReader(),
            new PkiFrameworkCertificateAuthorities([Certificates::AUTHORITY_PEM]),
        );
    }

    public static function selfSignedTlsClientAuth(?ClientKeySetProvider $keys = null): SelfSignedTlsClientAuth
    {
        return new SelfSignedTlsClientAuth($keys ?? self::keySetProvider());
    }

    public static function keySetProvider(
        ?ClientJwksFetcherInterface $fetcher = null,
        ?ClockInterface $clock = null,
        ?DateInterval $cooldown = null,
    ): ClientKeySetProvider {
        return new ClientKeySetProvider(new PublishedKeySetProvider(
            $fetcher ?? new FakeClientJwksFetcher([ClientAssertions::publishedKeys()]),
            new InMemoryClientJwksCache(),
            $clock ?? new MockClock('2026-09-15T12:00:00+00:00'),
            $cooldown ?? new DateInterval('PT300S'),
        ));
    }

    /**
     * RFC 7523 §2.2
     */
    public static function requestParser(?CompactJwtReaderInterface $reader = null): ClientAuthenticationRequestParser
    {
        return new ClientAuthenticationRequestParser($reader ?? new JwtLibraryCompactJwtReader());
    }

    public static function assertionValidator(
        ?ClientAssertionReplayGuardInterface $replays = null,
        ?AcceptedAssertionAudiences $audiences = null,
    ): ClientAssertionValidator {
        return new ClientAssertionValidator(
            $replays ?? new InMemoryClientAssertionReplayGuard(),
            $audiences ?? self::acceptedAudiences(),
            new DateInterval('PT300S'),
            new DateInterval('PT30S'),
        );
    }

    public static function acceptedAudiences(?ServedGrantsInterface $grants = null, ?string $mutualTlsOrigin = null): AcceptedAssertionAudiences
    {
        $endpoints = new Endpoints($mutualTlsOrigin);

        return new AcceptedAssertionAudiences($endpoints, $endpoints, $grants ?? Grants::served());
    }

    public static function all(
        ?PasswordHasherInterface $hasher = null,
        ?ClientKeySetProvider $keys = null,
        ?ClientAssertionValidator $claims = null,
    ): ClientAuthenticationMethods {
        $hasher ??= new FakePasswordHasher();
        $decoy = new DecoyHash($hasher, new SymfonyUuidGenerator(), new FakeMonotonicClock());
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
