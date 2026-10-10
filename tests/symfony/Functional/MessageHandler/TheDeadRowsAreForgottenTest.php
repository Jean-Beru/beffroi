<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\MessageHandler;

use Beffroi\Bundle\Doctrine\Repository\DoctrineRefreshTokenRepository;
use Beffroi\Bundle\Message\ForgetTheRecordsThatAreDead;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
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

/**
 * Issue #177: a row that can no longer do anything is dropped, and nothing else is.
 *
 * One case per kind, the row written at the moment that makes its retention end exactly now, then played
 * one minute on either side of it. **The retentions are two and not nine.** A row whose own expiry is the
 * end of it goes at that expiry: an interaction, a pushed request, an opaque access token of any of its
 * three kinds. A row an access token still needs waits what WhatATokenStillNeeds comes to, that being the
 * question a resource server asks of it: the three records a grant can be written in, and the login the
 * grant was given on.
 */
final class TheDeadRowsAreForgottenTest extends DatabaseTestCase
{
    /**
     * How long a row whose own expiry is the end of it is kept past that expiry: nothing at all. Nobody
     * reads it again, so there is nothing to wait for.
     */
    private const string AT_ITS_EXPIRY = '-0 seconds';

    /**
     * How long a row an access token still needs is kept past the instant it stopped granting, on the
     * lifetimes the test kernel configures: the absolute lifetime of a refresh token family, then the
     * lifetime of the last access token that family can mint.
     */
    private const string STILL_NEEDED = '-90 days -600 seconds';

    /**
     * How long an interaction of this test is parked for, and how long the device and backchannel records
     * of the fixtures live: a number the test chooses, so that only the retention is under test.
     */
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
     * Each kind, how long it is kept past the instant it stopped granting, and the table that holds it.
     * The instant the row stopped granting is the one the case plays on either side of; what the row's own
     * lifetime was before it is written() and not a retention.
     *
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

    /**
     * RFC 9700 §4.13.2: a rotated token stays so that its reuse is told from a token nobody issued, and
     * its own sliding expiry is not what ends that. Thirty days past that expiry, the family it belongs to
     * can still be refreshed, and the row is there.
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

    /**
     * The foreign key of a token to its family cascades nothing, so a family goes only once no token names
     * it. A statement bounded to one row leaves the second token of a lineage of two, and the family is
     * left where it is rather than failing the run.
     */
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

    /**
     * The present of the kernel, which is what the step reads; the fixtures are written against it so that
     * only the retention decides.
     */
    private static function present(): DateTimeImmutable
    {
        return self::service('clock', ClockInterface::class)->now();
    }

    private static function tick(): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch(new ForgetTheRecordsThatAreDead());
        self::reload();
    }

    /**
     * The store of the refresh tokens asked for one row, which is the budget its tokens spend before its
     * families are reached.
     */
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

    /**
     * A lineage of two, the second rotated from the first, both of a family whose absolute lifetime is up.
     */
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

    /**
     * One row of the kind named, written as if the provider had written it so that it stopped being able to
     * grant anything at the moment given.
     */
    private static function write(string $kind, DateTimeImmutable $stoppedGranting): void
    {
        $client = self::client();
        match ($kind) {
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
