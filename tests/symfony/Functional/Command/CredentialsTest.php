<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Command;

use Beffroi\Core\Tests\Fixture\Fixtures;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Credential\RevocableCredentialInterface;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\MetadataBlobStoreInterface;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use function preg_replace;
use function random_bytes;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.5: the console lists the credentials of a user and revokes a passkey, the only
 * administration of spike 3.
 */
final class CredentialsTest extends ConsoleTestCase
{
    #[Test]
    public function theUserIsShownWithTheCredentialsTheirKindNameAndDates(): void
    {
        // Given
        $user = self::user('alice');
        $password = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Argon2id(), '$argon2id$alice'), self::now());
        $passkey = self::passkey($user);
        $passkey->markUsed(self::now()->modify('+1 hour'));
        $passkey->revoke(self::now()->modify('+2 hours'));
        self::credentials()->save($password);
        self::credentials()->save($passkey);

        // When
        $tester = self::console('beffroi:user:show', [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $display = self::string(preg_replace('/ +/', ' ', $tester->getDisplay(true)));
        static::assertStringContainsString('password ' . $password->id->toRfc4122() . ' 2026-09-15 10:00:00', $display);
        static::assertStringContainsString(
            'passkey '
            . $passkey->id->toRfc4122()
            . ' YubiKey 5 unknown (AAGUID '
            . $passkey->aaguid->toRfc4122()
            . ') 2026-09-15 10:00:00 2026-09-15 11:00:00 2026-09-15 12:00:00',
            $display,
        );
    }

    /**
     * Issue #983: the authenticator of a passkey is named as the page of the passkeys names it, with its source.
     */
    #[Test]
    public function theAuthenticatorOfAPasskeyIsShownWithTheSourceThatNamesIt(): void
    {
        // Given
        $user = self::user('alice');
        $passkey = self::passkey($user);
        self::credentials()->save($passkey);
        self::service('test.beffroi.metadata_store', MetadataBlobStoreInterface::class)
            ->write(
                'mds-user-show',
                MetadataBlobs::payload([MetadataBlobs::entry($passkey->aaguid->toRfc4122(), description: 'YubiKey 5 Series')]),
            );

        // When
        $tester = self::console('beffroi:user:show', [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $display = self::string(preg_replace('/ +/', ' ', $tester->getDisplay(true)));
        static::assertStringContainsString('passkey ' . $passkey->id->toRfc4122() . ' YubiKey 5 YubiKey 5 Series (fido-metadata) 2026-09-15', $display);
    }

    #[Test]
    public function aUserWithoutCredentialIsShownAsSuch(): void
    {
        // Given
        self::user('alice');

        // When
        $tester = self::console('beffroi:user:show', [
            'username' => 'alice',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The user has no credential.', $tester->getDisplay(true));
    }

    #[Test]
    public function aPasskeyIsRevokedByItsIdentifierAndAnnouncedWithTheContextOfTheConsole(): void
    {
        // Given
        $user = self::user('alice');
        $passkey = self::passkey($user);
        self::credentials()->save($passkey);

        // When
        $tester = self::console('beffroi:user:revoke-credential', [
            'username' => 'alice',
            'id' => $passkey->id->toRfc4122(),
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The passkey "YubiKey 5" of the user "alice" is revoked; it never authenticates again.', self::flattened($tester));
        $revoked = self::credentials()->find($passkey->id) ?? static::fail('The passkey is gone.');
        static::assertInstanceOf(RevocableCredentialInterface::class, $revoked);
        static::assertTrue($revoked->isRevoked());
        $events = self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events;
        static::assertCount(1, $events);
        static::assertInstanceOf(CredentialRevoked::class, $events[0]);
        static::assertTrue($events[0]->credential->id->equals($passkey->id));
        static::assertNull($events[0]->context->ipAddress);
        static::assertStringStartsWith('beffroi-console/beffroi:user:revoke-credential (', $events[0]->context->userAgent ?? '');
    }

    /**
     * Issue #91: the TOTP is revoked from the console like a passkey, by the identifier beffroi:user:show
     * lists; the kind has no label, the identifier stands for it.
     */
    #[Test]
    public function aTotpIsRevokedByItsIdentifier(): void
    {
        // Given
        $user = self::user('alice');
        $totp = Totps::credential($user, new FakePasswordHasher());
        self::credentials()->save($totp);

        // When
        $tester = self::console('beffroi:user:revoke-credential', [
            'username' => 'alice',
            'id' => $totp->id->toRfc4122(),
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'The totp "' . $totp->id->toRfc4122() . '" of the user "alice" is revoked; it never authenticates again.',
            self::flattened($tester),
        );
        $revoked = self::credentials()->find($totp->id) ?? static::fail('The TOTP is gone.');
        static::assertInstanceOf(RevocableCredentialInterface::class, $revoked);
        static::assertTrue($revoked->isRevoked());
        static::assertCount(1, self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events);
    }

    #[Test]
    public function aSecondRevocationSaysWhenTheFirstHappenedAndAnnouncesNothing(): void
    {
        // Given
        $user = self::user('alice');
        $passkey = self::passkey($user);
        $passkey->revoke(self::now());
        self::credentials()->save($passkey);

        // When
        $tester = self::console('beffroi:user:revoke-credential', [
            'username' => 'alice',
            'id' => $passkey->id->toRfc4122(),
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The passkey "YubiKey 5" was revoked on 2026-09-15 10:00:00 already.', self::flattened($tester));
        static::assertSame([], self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events);
    }

    #[Test]
    public function aPasswordIsNotRevoked(): void
    {
        // Given
        $user = self::user('alice');
        $password = new PasswordCredential(Uuid::v7(), $user, new PasswordHash(new Argon2id(), '$argon2id$alice'), self::now());
        self::credentials()->save($password);

        // When
        $tester = self::console('beffroi:user:revoke-credential', [
            'username' => 'alice',
            'id' => $password->id->toRfc4122(),
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'The password "' . $password->id->toRfc4122() . '" cannot be revoked; a password is replaced, not revoked.',
            self::flattened($tester),
        );
    }

    #[Test]
    public function aCredentialOfAnotherUserIsNotFound(): void
    {
        // Given
        $passkey = self::passkey(self::user('bob', 'bob-subject'));
        self::credentials()->save($passkey);
        self::user('alice');

        // When
        $tester = self::console('beffroi:user:revoke-credential', [
            'username' => 'alice',
            'id' => $passkey->id->toRfc4122(),
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('The user "alice" has no credential "' . $passkey->id->toRfc4122() . '".', self::flattened($tester));
        $found = self::credentials()->find($passkey->id) ?? static::fail('The passkey is gone.');
        static::assertInstanceOf(RevocableCredentialInterface::class, $found);
        static::assertFalse($found->isRevoked());
    }

    #[Test]
    public function anIdentifierThatIsNotOneIsRefusedBeforeAnyLookup(): void
    {
        // When
        $tester = self::console('beffroi:user:revoke-credential', [
            'username' => 'nobody',
            'id' => 'not-a-uuid',
        ]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('"not-a-uuid" is not the identifier of a credential.', self::flattened($tester));
    }

    #[Test]
    public function anUnknownUserIsRefused(): void
    {
        // When
        $tester = self::console('beffroi:user:revoke-credential', [
            'username' => 'nobody',
            'id' => Uuid::v7()->toRfc4122(),
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('There is no user named "nobody"', self::flattened($tester));
    }

    private static function passkey(User $user): PasskeyCredential
    {
        return new PasskeyCredential(
            Uuid::v7(),
            $user,
            'YubiKey 5',
            random_bytes(16),
            'cose-public-key',
            0,
            ['usb'],
            false,
            false,
            Uuid::v4(),
            Fixtures::userHandle(),
            self::now(),
        );
    }

    private static function credentials(): CredentialRepositoryInterface
    {
        return self::service('test.beffroi.credentials', CredentialRepositoryInterface::class);
    }
}
