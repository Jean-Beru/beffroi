<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Doctrine\Repository\DoctrineRefreshTokenRepository;
use App\Message\ForgetTheRecordsThatAreDead;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Symfony\Component\Uid\Uuid;
use Beffroi\Core\Port\EnrolmentTicketRepositoryInterface;
use Beffroi\Core\Port\PasswordTicketRepositoryInterface;
use Beffroi\Core\Port\TotpTicketRepositoryInterface;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Ticket\PasswordTicket;
use Beffroi\Core\Domain\Ticket\TotpTicket;
use Beffroi\Core\Domain\Confirmation\EmailConfirmation;
use Beffroi\Core\Domain\Confirmation\PhoneNumberConfirmation;
use Beffroi\Core\Port\AddressConfirmationRepositoryInterface;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Messenger\MessageBusInterface;

final class TheDeadRowsAreForgottenTest extends DatabaseTestCase
{
    private const string AT_ITS_EXPIRY = '-0 seconds';

    private const string STILL_NEEDED = '-90 days -600 seconds';

    private const string TEN_MINUTES = '-600 seconds';

    #[Test]
    #[DataProvider('provideKinds')]
    public function aRowInsideItsRetentionIsKept(string $kind, string $retention, string $table): void
    {
        // Given
        self::write($kind, self::present()->modify($retention)->modify('+1 minute'));

        // When
        self::tick();

        // Then
        static::assertSame(1, self::rowsIn($table));
    }

    #[Test]
    #[DataProvider('provideKinds')]
    public function aRowPastItsRetentionIsDropped(string $kind, string $retention, string $table): void
    {
        // Given
        self::write($kind, self::present()->modify($retention)->modify('-1 minute'));

        // When
        self::tick();

        // Then
        static::assertSame(0, self::rowsIn($table));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function provideKinds(): iterable
    {
        yield 'an interaction, worth nothing once it cannot be resumed' => [
            'interaction',
            self::AT_ITS_EXPIRY,
            'beffroi_interaction',
        ];
        yield 'a pushed request, worth nothing once its reference has expired' => [
            'pushedRequest',
            self::AT_ITS_EXPIRY,
            'beffroi_pushed_authorization_request',
        ];
        yield 'an opaque access token somebody signed in for' => [
            'accessToken',
            self::AT_ITS_EXPIRY,
            'beffroi_access_token',
        ];
        yield 'an opaque access token a client holds for itself' => [
            'clientAccessToken',
            self::AT_ITS_EXPIRY,
            'beffroi_client_access_token',
        ];
        yield 'an opaque access token whose subject was presented' => [
            'subjectAccessToken',
            self::AT_ITS_EXPIRY,
            'beffroi_subject_access_token',
        ];
        yield 'an enrolment ticket, worth nothing once it is out of time' => [
            'enrolmentTicket',
            self::AT_ITS_EXPIRY,
            'beffroi_enrolment_ticket',
        ];
        yield 'a password ticket, worth nothing once it is out of time' => [
            'passwordTicket',
            self::AT_ITS_EXPIRY,
            'beffroi_password_ticket',
        ];
        yield 'a one-time password ticket, worth nothing once it is out of time' => [
            'totpTicket',
            self::AT_ITS_EXPIRY,
            'beffroi_totp_ticket',
        ];
        yield 'a confirmation of an email address, worth nothing once it is out of time' => [
            'emailConfirmation',
            self::AT_ITS_EXPIRY,
            'beffroi_email_confirmation',
        ];
        yield 'a confirmation of a phone number, worth nothing once it is out of time' => [
            'phoneNumberConfirmation',
            self::AT_ITS_EXPIRY,
            'beffroi_phone_number_confirmation',
        ];
        yield 'an authorization code, which is the grant its tokens descend from' => [
            'code',
            self::STILL_NEEDED,
            'beffroi_authorization_code',
        ];
        yield 'a device authorization request, a grant as well' => [
            'deviceRecord',
            self::STILL_NEEDED,
            'beffroi_device_authorization_request',
        ];
        yield 'a backchannel authentication request, a grant as well' => [
            'backchannelRecord',
            self::STILL_NEEDED,
            'beffroi_backchannel_authentication_request',
        ];
        yield 'a session, which an access token of it names' => [
            'session',
            self::STILL_NEEDED,
            'beffroi_authentication_session',
        ];
    }

    #[Test]
    public function anEnrolmentTicketSpentIsDroppedBeforeItsTime(): void
    {
        // Given
        $tickets = self::service('test.beffroi.enrolment_ticket_store', EnrolmentTicketRepositoryInterface::class);
        $ticket = new EnrolmentTicket(
            Uuid::v7(),
            self::user(),
            new PasswordHash(new Argon2id(), '$argon2id$the-value-of-a-link'),
            self::present(),
            self::present()->modify('+72 hours'),
        );
        $ticket->spend(self::present());
        $tickets->save($ticket);

        // When
        self::tick();

        // Then
        static::assertSame(0, self::rowsIn('beffroi_enrolment_ticket'));
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function aRotatedRefreshTokenOutlivesItsOwnExpiry(): void
    {
        // Given
        $issuedAt = self::present()->modify('-60 days');
        $token = Tokens::refreshToken(Secrets::draw(), self::client(), self::session(self::user(), $issuedAt), $issuedAt);
        $token->rotate($issuedAt);
        self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class)->save($token);
        self::reload();

        // When
        self::tick();

        // Then
        static::assertSame(1, self::rowsIn('beffroi_refresh_token'));
    }

    #[Test]
    public function aRefreshTokenWhoseFamilyIsOverIsDroppedWithIt(): void
    {
        // Given
        self::aTokenOfAFamilyThatIsOver();

        // When
        self::tick();

        // Then
        static::assertSame(0, self::rowsIn('beffroi_refresh_token'));
        static::assertSame(0, self::rowsIn('beffroi_refresh_token_family'));
    }

    #[Test]
    public function aFamilyOneOfWhoseTokensIsStillThereIsLeftToTheNextRun(): void
    {
        // Given
        self::twoTokensOfAFamilyThatIsOver();

        // When
        self::sweepWithRoomForOneRow();

        // Then
        static::assertSame(1, self::rowsIn('beffroi_refresh_token'));
        static::assertSame(1, self::rowsIn('beffroi_refresh_token_family'));
    }

    private static function present(): DateTimeImmutable
    {
        return self::service('clock', ClockInterface::class)->now();
    }

    private static function tick(): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch(new ForgetTheRecordsThatAreDead());
        self::reload();
    }

    private static function sweepWithRoomForOneRow(): void
    {
        self::service('test.beffroi.dead_refresh_tokens', DoctrineRefreshTokenRepository::class)->forgetWhatIsDead(self::tenant(), self::present(), 1);
        self::reload();
    }

    private static function aTokenOfAFamilyThatIsOver(): void
    {
        $issuedAt = self::present()->modify('-91 days');
        self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class)
            ->save(Tokens::refreshToken(Secrets::draw(), self::client(), self::session(self::user(), $issuedAt), $issuedAt));
        self::reload();
    }

    private static function twoTokensOfAFamilyThatIsOver(): void
    {
        $issuedAt = self::present()->modify('-91 days');
        $client = self::client();
        $session = self::session(self::user(), $issuedAt);
        $family = Tokens::family($issuedAt, self::tenant());
        $tokens = self::service('test.beffroi.refresh_tokens', RefreshTokenRepositoryInterface::class);
        $tokens->save(Tokens::refreshToken(Secrets::draw(), $client, $session, $issuedAt, $family));
        $tokens->save(Tokens::refreshToken(Secrets::draw(), $client, $session, $issuedAt->modify('+1 hour'), $family));
        self::reload();
    }

    private static function rowsIn(string $table): int
    {
        $value = self::service('doctrine.dbal.default_connection', Connection::class)->fetchOne(sprintf('SELECT COUNT(*) FROM %s', $table));
        static::assertIsNumeric($value);

        return (int) $value;
    }

    private static function write(string $kind, DateTimeImmutable $stoppedGranting): void
    {
        $client = self::client();
        match ($kind) {
            'enrolmentTicket' => self::service('test.beffroi.enrolment_ticket_store', EnrolmentTicketRepositoryInterface::class)
                ->save(new EnrolmentTicket(
                    Uuid::v7(),
                    self::user(),
                    new PasswordHash(new Argon2id(), '$argon2id$the-value-of-a-link'),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                    $stoppedGranting,
                )),
            'passwordTicket' => self::service('test.beffroi.password_ticket_store', PasswordTicketRepositoryInterface::class)
                ->save(new PasswordTicket(
                    Uuid::v7(),
                    self::user(),
                    new PasswordHash(new Argon2id(), '$argon2id$the-value-of-a-link'),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                    $stoppedGranting,
                )),
            'totpTicket' => self::service('test.beffroi.totp_ticket_store', TotpTicketRepositoryInterface::class)
                ->save(new TotpTicket(
                    Uuid::v7(),
                    self::user(),
                    new PasswordHash(new Argon2id(), '$argon2id$the-value-of-a-link'),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                    $stoppedGranting,
                )),
            'emailConfirmation' => self::service('test.beffroi.email_confirmation_store', AddressConfirmationRepositoryInterface::class)
                ->save(new EmailConfirmation(
                    Uuid::v7(),
                    self::user(),
                    new PasswordHash(new Argon2id(), '$argon2id$the-code'),
                    new PasswordHash(new Argon2id(), '$argon2id$the-value-of-a-link'),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                    $stoppedGranting,
                )),
            'phoneNumberConfirmation' => self::service('test.beffroi.phone_number_confirmation_store', AddressConfirmationRepositoryInterface::class)
                ->save(new PhoneNumberConfirmation(
                    Uuid::v7(),
                    self::user(),
                    new PasswordHash(new Argon2id(), '$argon2id$the-code'),
                    new PasswordHash(new Argon2id(), '$argon2id$the-value-of-a-link'),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                    $stoppedGranting,
                )),
            'interaction' => self::service('test.beffroi.interactions', InteractionRepositoryInterface::class)
                ->save(new Interaction(
                    Secrets::draw(),
                    self::tenant(),
                    Requests::authorization($client),
                    null,
                    $stoppedGranting->modify(self::TEN_MINUTES),
                    $stoppedGranting,
                )),
            'pushedRequest' => self::service('test.beffroi.pushed_authorization_requests', PushedAuthorizationRecordRepositoryInterface::class)
                ->save(new PushedAuthorizationRecord(
                    DrawnSecret::digestOf(Secrets::draw()),
                    $client,
                    [
                        'scope' => 'openid',
                    ],
                    $stoppedGranting->modify('-60 seconds'),
                    $stoppedGranting,
                )),
            'accessToken' => self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class)
                ->save(Tokens::storedAccessToken(
                    Secrets::draw(),
                    $client,
                    self::session(self::user(), $stoppedGranting->modify(self::TEN_MINUTES)),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                )),
            'clientAccessToken' => self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class)
                ->save(Tokens::storedClientAccessToken(Secrets::draw(), $client, $stoppedGranting->modify(self::TEN_MINUTES))),
            'subjectAccessToken' => self::service('test.beffroi.access_tokens_store', AccessTokenRepositoryInterface::class)
                ->save(Tokens::storedSubjectAccessToken(
                    Secrets::draw(),
                    $client,
                    new Subject('alice-subject'),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                )),
            'code' => self::service('test.beffroi.authorization_codes', AuthorizationCodeRepositoryInterface::class)
                ->save(Tokens::code(
                    Secrets::draw(),
                    $client,
                    self::session(self::user(), $stoppedGranting->modify('-60 seconds')),
                    $stoppedGranting->modify('-60 seconds'),
                )),
            'deviceRecord' => self::service('test.beffroi.device_authorization_requests', DeviceAuthorizationRecordRepositoryInterface::class)
                ->save(Tokens::approvedDeviceRecord(
                    $client,
                    self::session(self::user(), $stoppedGranting->modify(self::TEN_MINUTES)),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                )),
            'backchannelRecord' => self::service('test.beffroi.backchannel_authentication_requests', BackchannelAuthenticationRecordRepositoryInterface::class)
                ->save(Tokens::approvedBackchannelRecord(
                    $client,
                    self::session(self::user(), $stoppedGranting->modify(self::TEN_MINUTES)),
                    $stoppedGranting->modify(self::TEN_MINUTES),
                )),
            'session' => self::session(self::user(), $stoppedGranting->modify('-12 hours')),
            default => static::fail(sprintf('No row of the kind "%s" is written here.', $kind)),
        };
        self::reload();
    }
}
