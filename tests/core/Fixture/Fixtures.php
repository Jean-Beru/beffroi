<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function chr;
use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Webauthn\StoredMetadata;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Credential\PasskeyUserHandle;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\MetadataBlobStoreInterface;
use Psr\Clock\ClockInterface;
use function str_repeat;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorData;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;

final class Fixtures
{
    /**
     * The address every provenance of the fixtures came from, read from here by whatever answers something
     * of that address (GeoLocatorOfPlaces): two lists of the same address are two lists that disagree.
     */
    public const string IP_ADDRESS = '203.0.113.10';

    /**
     * A handle of the shape an authenticator stores, for a test that does not care which.
     */
    public static function userHandle(): PasskeyUserHandle
    {
        return new PasskeyUserHandle(new PlatformRandomness()->bytes(PasskeyUserHandle::LENGTH));
    }

    public static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-09-15T10:00:00+00:00');
    }

    public static function tenant(
        string $slug = 'acme',
        string $issuer = 'https://id.acme.example',
        ?AuthenticationPredicate $loginFloor = null,
    ): Tenant {
        return new Tenant(Uuid::v7(), $slug, new Issuer($issuer), 'Acme', self::now(), loginFloor: $loginFloor);
    }

    /**
     * A tenant that signs its users in by passkey and forbids the password (issue #327).
     */
    public static function hardenedTenant(string $slug = 'acme'): Tenant
    {
        return self::tenant($slug, loginFloor: AuthenticationPredicate::PhishingResistant);
    }

    public static function context(
        ?DateTimeImmutable $receivedAt = null,
        ?string $ipAddress = self::IP_ADDRESS,
        ?string $userAgent = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0',
    ): RequestContext {
        return new RequestContext($receivedAt ?? self::now(), $ipAddress, $userAgent);
    }

    /**
     * @param AuthenticationProofs|null $proofs a password proven at the authentication instant when null
     */
    public static function session(?User $user = null, ?DateTimeImmutable $authenticatedAt = null, ?AuthenticationProofs $proofs = null): AuthenticationSession
    {
        $user ??= self::user();
        $authenticatedAt ??= self::now();

        return new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            $authenticatedAt,
            $proofs ?? AuthenticationProofs::of(AuthenticationMethod::password(), $authenticatedAt),
            self::context($authenticatedAt),
            $authenticatedAt->modify('+12 hours'),
        );
    }

    /**
     * A password, hashed by the fake hasher.
     */
    public static function password(?User $user = null, ?DateTimeImmutable $createdAt = null): PasswordCredential
    {
        return new PasswordCredential(
            Uuid::v7(),
            $user ?? self::user(),
            new FakePasswordHasher()->hash('correct horse battery staple'),
            $createdAt ?? self::now(),
        );
    }

    /**
     * A device-bound passkey, unused, with a handle of its own unless one is given.
     */
    public static function passkey(
        ?User $user = null,
        string $name = 'YubiKey 5',
        string $credentialId = 'credential-id',
        ?PasskeyUserHandle $userHandle = null,
        bool $backupEligible = false,
        bool $backedUp = false,
        ?DateTimeImmutable $createdAt = null,
    ): PasskeyCredential {
        return new PasskeyCredential(
            Uuid::v7(),
            $user ?? self::user(),
            $name,
            $credentialId,
            'cose-public-key',
            0,
            ['usb'],
            $backupEligible,
            $backedUp,
            Uuid::v4(),
            $userHandle ?? self::userHandle(),
            $createdAt ?? self::now(),
        );
    }

    /**
     * The authenticator data of an assertion (WebAuthn Level 3 §6.1), its flags chosen by the test.
     */
    public static function authenticatorData(
        bool $userPresent = true,
        bool $userVerified = false,
        bool $backupEligible = false,
        bool $backedUp = false,
        int $signCount = 0,
    ): AuthenticatorData {
        $flags =
            ($userPresent ? AuthenticatorData::FLAG_UP : 0)
            | ($userVerified ? AuthenticatorData::FLAG_UV : 0)
            | ($backupEligible ? AuthenticatorData::FLAG_BE : 0)
            | ($backedUp ? AuthenticatorData::FLAG_BS : 0);

        return AuthenticatorData::create('', str_repeat("\0", 32), chr($flags), $signCount);
    }

    public static function user(?Tenant $tenant = null, string $username = 'alice', string $subject = 'alice-subject'): User
    {
        return User::create(Uuid::v7(), $tenant ?? self::tenant(), new Subject($subject), $username, self::now());
    }

    /**
     * The ceremonies on the metadata of a store, empty unless one is given; the chains are checked
     * without a CRL fetched, as the library does when none can be.
     */
    public static function ceremonies(?MetadataBlobStoreInterface $metadata = null, ?ClockInterface $clock = null): WebauthnCeremonies
    {
        $clock ??= new MockClock(self::now());
        $stored = new StoredMetadata($metadata ?? new InMemoryMetadataBlobStore());

        return new WebauthnCeremonies($clock, $stored, $stored, PhpCertificateChainValidator::create(new MockHttpClient(), $clock));
    }
}
