<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use function chr;
use DateTimeImmutable;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Credential\PasskeyUserHandle;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use function str_repeat;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorData;

final class Fixtures
{
    public static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-09-15T10:00:00+00:00');
    }

    public static function tenant(string $slug = 'acme', string $issuer = 'https://id.acme.example'): Tenant
    {
        return new Tenant(Uuid::v7(), $slug, new Issuer($issuer), 'Acme', self::now());
    }

    public static function context(?DateTimeImmutable $receivedAt = null, ?string $ipAddress = '203.0.113.10', ?string $userAgent = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0'): RequestContext
    {
        return new RequestContext($receivedAt ?? self::now(), $ipAddress, $userAgent);
    }

    /**
     * @param AuthenticationProofs|null $proofs a password proven at the authentication instant when null
     */
    public static function session(?User $user = null, ?DateTimeImmutable $authenticatedAt = null, ?AuthenticationProofs $proofs = null): AuthenticationSession
    {
        $user ??= self::user();
        $authenticatedAt ??= self::now();

        return new AuthenticationSession(Uuid::v7(), $user->tenant, $user, $authenticatedAt, $proofs ?? AuthenticationProofs::of(AuthenticationMethod::password(), $authenticatedAt), self::context($authenticatedAt), $authenticatedAt->modify('+12 hours'));
    }

    /**
     * A device-bound passkey, unused, with a handle of its own unless one is given.
     */
    public static function passkey(?User $user = null, string $name = 'YubiKey 5', string $credentialId = 'credential-id', ?PasskeyUserHandle $userHandle = null, bool $backupEligible = false, bool $backedUp = false, ?DateTimeImmutable $createdAt = null): PasskeyCredential
    {
        return new PasskeyCredential(Uuid::v7(), $user ?? self::user(), $name, $credentialId, 'cose-public-key', 0, ['usb'], $backupEligible, $backedUp, Uuid::v4(), $userHandle ?? PasskeyUserHandle::generate(), $createdAt ?? self::now());
    }

    /**
     * The authenticator data of an assertion (WebAuthn Level 3 §6.1), its flags chosen by the test.
     */
    public static function authenticatorData(bool $userPresent = true, bool $userVerified = false, bool $backupEligible = false, bool $backedUp = false, int $signCount = 0): AuthenticatorData
    {
        $flags = ($userPresent ? AuthenticatorData::FLAG_UP : 0)
            | ($userVerified ? AuthenticatorData::FLAG_UV : 0)
            | ($backupEligible ? AuthenticatorData::FLAG_BE : 0)
            | ($backedUp ? AuthenticatorData::FLAG_BS : 0);

        return AuthenticatorData::create('', str_repeat("\0", 32), chr($flags), $signCount);
    }

    public static function user(?Tenant $tenant = null, string $username = 'alice', string $subject = 'alice-subject'): User
    {
        return User::create(Uuid::v7(), $tenant ?? self::tenant(), new Subject($subject), $username, self::now());
    }
}
