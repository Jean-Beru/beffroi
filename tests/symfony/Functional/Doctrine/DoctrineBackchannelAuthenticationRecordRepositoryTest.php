<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_map;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §7, §10.1, Architecture §5.3
 */
final class DoctrineBackchannelAuthenticationRecordRepositoryTest extends DatabaseTestCase
{
    /**
     * CIBA Core §10.1
     */
    #[Test]
    public function onlyTheFirstCallerSpendsTheIdentifier(): void
    {
        // Given
        $authRequestId = Secrets::draw();
        self::records()->save(self::record($authRequestId, self::client('terminal-app'), self::user()));
        self::reload();
        $record = self::records()->findByAuthRequestIdHash(DrawnSecret::digestOf($authRequestId)) ?? static::fail('The record was not stored.');

        // When
        $first = self::records()->consume($record, self::now());
        $second = self::records()->consume($record, self::now()->modify('+1 second'));

        // Then
        static::assertTrue($first);
        static::assertFalse($second);
        static::assertEquals(self::now(), $record->usedAt);
    }

    #[Test]
    public function aRecordComesBackWithWhatTheGrantNeeds(): void
    {
        // Given
        $authRequestId = Secrets::draw();
        $alice = self::user();
        self::records()->save(self::record($authRequestId, self::client('terminal-app'), $alice));
        self::reload();

        // When
        $found = self::records()->findByAuthRequestIdHash(DrawnSecret::digestOf($authRequestId)) ?? static::fail('The record was not stored.');

        // Then
        static::assertSame(DrawnSecret::digestOf($authRequestId), $found->authRequestIdHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('terminal-app', $found->clientId);
        static::assertSame('terminal-app', $found->client->registration->clientId);
        static::assertTrue($found->user?->id->equals($alice->id));
        static::assertEquals([new Scope('openid'), new Scope('profile')], $found->scopes->all);
        static::assertEquals([new ResourceIndicator('https://cal.example.com/')], $found->resources?->all);
        static::assertSame('Payment of 42 euros', $found->bindingMessage?->value);
        static::assertSame('203.0.113.10', $found->requestedFrom->ipAddress);
        static::assertSame(5, $found->interval);
        static::assertEquals(self::now()->modify('+5 minutes'), $found->expiresAt);
        static::assertFalse($found->isAnswered());
        static::assertFalse($found->isUsed());
        static::assertNull($found->session);
        static::assertNull($found->authentication);
    }

    /**
     * CIBA Core §10.2
     */
    #[Test]
    public function whatIsKeptForAClientThatIsCalledBackComesBackAsItWasSealed(): void
    {
        // Given
        $authRequestId = Secrets::draw();
        self::records()
            ->save(self::record(
                $authRequestId,
                self::client('terminal-app'),
                self::user(),
                sealedAuthRequestId: 'sealed-identifier-bytes',
                sealedNotificationToken: 'sealed-token-bytes',
            ));
        self::reload();

        // When
        $found = self::records()->findByAuthRequestIdHash(DrawnSecret::digestOf($authRequestId)) ?? static::fail('The record was not stored.');

        // Then
        static::assertSame('sealed-identifier-bytes', $found->sealedAuthRequestId);
        static::assertSame('sealed-token-bytes', $found->sealedNotificationToken);
    }

    /**
     * CIBA Core §10.1
     */
    #[Test]
    public function anApprovalComesBackWithItsSessionAndWhatItHadProven(): void
    {
        // Given
        $authRequestId = Secrets::draw();
        $alice = self::user();
        $session = self::session($alice);
        $record = self::record($authRequestId, self::client('terminal-app'), $alice);
        $record->approve($session, new AuthenticationSnapshot(self::now(), ['pwd'], '1'), self::now()->modify('+30 seconds'));
        self::records()->save($record);
        self::reload();

        // When
        $found = self::records()->findByAuthRequestIdHash(DrawnSecret::digestOf($authRequestId)) ?? static::fail('The record was not stored.');

        // Then
        static::assertTrue($found->isApproved());
        static::assertTrue($found->session?->id->equals($session->id));
        $authentication = $found->authentication ?? static::fail('The approval kept nothing of what the session had proven.');
        static::assertEquals(self::now(), $authentication->authenticatedAt);
        static::assertSame(['pwd'], $authentication->methods);
        static::assertSame('1', $authentication->contextClass);
        static::assertEquals(self::now()->modify('+30 seconds'), $found->approvedAt);
    }

    /**
     * CIBA Core §10.1
     */
    #[Test]
    public function whatIsWaitingIsReadByTheUserItWasMadeFor(): void
    {
        // Given
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        $client = self::client('terminal-app');
        self::records()->save(self::record(Secrets::draw(), $client, $bob));
        $first = Secrets::draw();
        self::records()->save(self::record($first, $client, $alice));
        $second = Secrets::draw();
        self::records()->save(self::record($second, $client, $alice, issuedAt: self::now()->modify('+10 seconds')));
        self::reload();

        // When
        $waiting = self::records()->awaitingAnAnswerBy($alice, self::now());

        // Then
        static::assertSame(
            [DrawnSecret::digestOf($first), DrawnSecret::digestOf($second)],
            array_map(static fn (BackchannelAuthenticationRecord $record): string => $record->authRequestIdHash, $waiting),
        );
    }

    #[Test]
    public function whatIsNoLongerWaitingIsNotRead(): void
    {
        // Given
        $alice = self::user();
        $client = self::client('terminal-app');
        $denied = self::record(Secrets::draw(), $client, $alice);
        $denied->deny(self::now());
        self::records()->save($denied);
        $spent = self::record(Secrets::draw(), $client, $alice);
        $spent->consume(self::now());
        self::records()->save($spent);
        self::records()->save(self::record(Secrets::draw(), $client, $alice, issuedAt: self::now()->modify('-10 minutes')));
        self::reload();

        // When
        $waiting = self::records()->awaitingAnAnswerBy($alice, self::now());

        // Then
        static::assertSame([], $waiting);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function aRequestTakenBackWithItsConsentIsNotRead(): void
    {
        // Given
        $alice = self::user();
        $revoked = self::record(Secrets::draw(), self::client('terminal-app'), $alice);
        $revoked->revoke(self::now());
        self::records()->save($revoked);
        self::reload();

        // When
        $waiting = self::records()->awaitingAnAnswerBy($alice, self::now());

        // Then
        static::assertSame([], $waiting);
    }

    /**
     * CIBA Core §10.1
     */
    #[Test]
    public function aSpentRecordStaysSpent(): void
    {
        // Given
        $authRequestId = Secrets::draw();
        $record = self::record($authRequestId, self::client('terminal-app'), self::user());
        self::records()->save($record);
        $record->consume(self::now()->modify('+90 seconds'));
        self::records()->save($record);
        self::reload();

        // When
        $found = self::records()->findByAuthRequestIdHash(DrawnSecret::digestOf($authRequestId)) ?? static::fail('The record was not stored.');

        // Then
        static::assertTrue($found->isUsed());
        static::assertEquals(self::now()->modify('+90 seconds'), $found->usedAt);
    }

    #[Test]
    public function anIdentifierThisProviderNeverAnsweredIsFoundByNothing(): void
    {
        // When / Then
        static::assertNull(self::records()->findByAuthRequestIdHash(DrawnSecret::digestOf('never-answered')));
    }

    private static function records(): BackchannelAuthenticationRecordRepositoryInterface
    {
        return self::service('test.beffroi.backchannel_authentication_requests', BackchannelAuthenticationRecordRepositoryInterface::class);
    }

    private static function record(
        string $authRequestId,
        Client $client,
        User $user,
        ?string $sealedAuthRequestId = null,
        ?string $sealedNotificationToken = null,
        ?DateTimeImmutable $issuedAt = null,
    ): BackchannelAuthenticationRecord {
        $issuedAt ??= self::now();

        return new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf($authRequestId),
            Uuid::v7(),
            $client,
            $user,
            new Scopes([new Scope('openid'), new Scope('profile')]),
            new ResourceIndicators([new ResourceIndicator('https://cal.example.com/')]),
            new BindingMessage('Payment of 42 euros'),
            ['phr'],
            $sealedAuthRequestId,
            $sealedNotificationToken,
            self::context(),
            $issuedAt,
            $issuedAt->modify('+5 minutes'),
        );
    }
}
