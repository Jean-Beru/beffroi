<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Event;

use function array_map;
use function array_unique;
use function array_values;
use function basename;
use function class_exists;
use DateTimeImmutable;
use function dirname;
use function glob;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Event\BackupCodeUsed;
use Beffroi\Core\Domain\Event\BackupCodesRenewed;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\CredentialRenamed;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Event\CredentialForgotten;
use Beffroi\Core\Domain\Event\EnrolmentTicketIssued;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Domain\Event\LoadBudgetSpent;
use Beffroi\Core\Domain\Event\PasskeyUsed;
use Beffroi\Core\Domain\Event\PersonAskedForTheirArchive;
use Beffroi\Core\Domain\Event\PersonDescribedThemselves;
use Beffroi\Core\Domain\Event\PersonDroppedTheirArchive;
use Beffroi\Core\Domain\Event\PersonProvisioned;
use Beffroi\Core\Domain\Event\PersonTookTheirArchive;
use Beffroi\Core\Domain\Event\PasswordRehashed;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Event\TenantDataKeysDestroyed;
use Beffroi\Core\Domain\Event\TenantDataKeysRewrapped;
use Beffroi\Core\Domain\Event\TenantKeyRetired;
use Beffroi\Core\Domain\Event\TenantKeyRotated;
use Beffroi\Core\Domain\Event\TenantKeyStaged;
use Beffroi\Core\Domain\Event\TotpUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Key\RetirementReason;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Core\Tests\Fixture\Totps;
use function is_a;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use function serialize;
use function sort;
use function sprintf;
use function unserialize;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.6
 */
final class EventsLeaveTheProcessTest extends TestCase
{
    /**
     * @return iterable<string, array{DomainEventInterface}>
     */
    public static function events(): iterable
    {
        $now = Fixtures::now();
        $context = Fixtures::context();
        $session = Fixtures::session();
        $user = $session->user;
        $tenant = $session->tenant;
        $password = Fixtures::password($user);
        $passkey = Fixtures::passkey($user);
        $totp = Totps::credential($user, new FakePasswordHasher());
        $ended = Fixtures::session();
        $ended->end(SessionEnd::RelyingParty, $now);

        yield 'a user authenticated' => [new UserAuthenticated($session)];
        yield 'a session ended' => [new AuthenticationSessionEnded($ended, $now, $context)];
        yield 'an authentication that failed' => [new AuthenticationFailed(
            $now,
            $tenant,
            $context,
            AuthenticationMethod::password(),
            AuthenticationFailureReason::InvalidCredential,
            'alice',
            $user,
        )];
        yield 'a person an upstream provider created' => [new PersonProvisioned($now, $tenant, $user->subject, 'https://idp.acme.example/saml', $context)];
        yield 'a person who said something of themselves' => [new PersonDescribedThemselves($user, 'nickname', false, $now, $context)];
        yield 'a person who took something back' => [new PersonDescribedThemselves($user, 'nickname', true, $now, $context)];
        yield 'a person who asked for their archive' => [new PersonAskedForTheirArchive($now, $tenant, Uuid::v7(), $user->subject, $context)];
        yield 'a person who took their archive' => [new PersonTookTheirArchive($now, $tenant, Uuid::v7(), $user->subject, $context)];
        yield 'a person who dropped their archive' => [new PersonDroppedTheirArchive($now, $tenant, Uuid::v7(), $user->subject, $context)];
        yield 'a credential enrolled' => [new CredentialEnrolled($passkey, $now, $context)];
        yield 'a credential revoked' => [new CredentialRevoked($passkey, $now, $context)];
        yield 'a credential forgotten' => [new CredentialForgotten($password, $now, $context)];
        yield 'an enrolment ticket issued' => [new EnrolmentTicketIssued(
            new EnrolmentTicket(Uuid::v7(), $user, $password->hash, $now, $now->modify('+72 hours')),
            $now,
            $context,
        )];
        yield 'a credential renamed' => [new CredentialRenamed($passkey, 'The key it was', $now, $context)];
        yield 'a passkey used' => [new PasskeyUsed($passkey, $now, $context)];
        yield 'a password used' => [new PasswordUsed($password, $now, $context)];
        yield 'a password rehashed' => [new PasswordRehashed($password, $now, $context)];
        yield 'a password changed by the person who holds it' => [new PasswordChanged($password, $now, $context)];
        yield 'a TOTP used' => [new TotpUsed($totp, $now, $context)];
        yield 'a backup code spent' => [new BackupCodeUsed($totp, $now, $context)];
        yield 'backup codes renewed' => [new BackupCodesRenewed($totp, $now, $context)];
        yield 'a KMS that could not be reached' => [new KmsUnavailable($now, $tenant, $context, 'the KMS answered 503')];
        yield 'a load budget spent' => [new LoadBudgetSpent($now, $tenant, $context, 'login', 'beffroi_interaction_login', 'oidc-demo')];
        yield 'a key staged' => [new TenantKeyStaged(self::key($tenant, $now), $now, $context)];
        yield 'a key rotated' => [new TenantKeyRotated(self::key($tenant, $now), self::key($tenant, $now), $now, $context)];
        yield 'a key retired' => [new TenantKeyRetired(self::key($tenant, $now), RetirementReason::Due, $now, $context)];
        yield 'the data keys of a tenant rewrapped' => [new TenantDataKeysRewrapped(
            $tenant,
            11,
            10,
            'vault',
            'aws',
            'alias/beffroi-acme',
            $now,
            $context,
        )];
        yield 'the data keys of a tenant destroyed' => [new TenantDataKeysDestroyed($tenant, 11, 10, $now, $context)];
    }

    #[Test]
    #[DataProvider('events')]
    public function anEventIsWrittenToTheQueueAndReadBack(DomainEventInterface $event): void
    {
        // When
        $written = serialize($event);

        // Then
        static::assertInstanceOf($event::class, unserialize($written));
    }

    #[Test]
    public function everyEventOfThePackageIsWrittenToTheQueue(): void
    {
        // Given
        $covered = array_values(array_unique(array_map(static fn (array $case): string => $case[0]::class, [...self::events()])));
        sort($covered);

        // When
        $declared = self::declaredEvents();

        // Then
        static::assertSame($declared, $covered);
    }

    private static function key(Tenant $tenant, DateTimeImmutable $now): TenantKey
    {
        $pair = Keys::pair();

        return new TenantKey(
            $pair->kid,
            $tenant,
            $pair->algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($tenant, $pair->privateJwk),
            $now,
            $now,
        );
    }

    /**
     * @return list<class-string<DomainEventInterface>>
     */
    private static function declaredEvents(): array
    {
        $reflection = new ReflectionClass(UserAuthenticated::class);
        $file = $reflection->getFileName();
        if ($file === false) {
            static::fail('The events of the package are read from the directory of one of them.');
        }
        $files = glob(dirname($file) . '/*.php');
        if ($files === false) {
            static::fail(sprintf('The directory of the events cannot be read: %s.', dirname($file)));
        }
        $declared = [];
        foreach ($files as $candidate) {
            /** @var class-string $class */
            $class = $reflection->getNamespaceName() . '\\' . basename($candidate, '.php');
            if (class_exists($class) && is_a($class, DomainEventInterface::class, true)) {
                $declared[] = $class;
            }
        }
        sort($declared);

        return $declared;
    }
}
