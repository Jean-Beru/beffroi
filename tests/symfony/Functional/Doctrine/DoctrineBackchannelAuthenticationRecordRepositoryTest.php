<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Ciba\BindingMessage;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §7, §10.1, architecture §5.3: a backchannel authentication request keyed by the hash of the
 * identifier its client comes back with, found again by the user it was made for; a spent record stays.
 */
final class DoctrineBackchannelAuthenticationRecordRepositoryTest extends DatabaseTestCase
{
    /**
     * §10.1: the claim is one conditional statement, so a second caller is told it lost, and it holds the
     * date the first one wrote.
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

    /**
     * What the token endpoint needs of a record comes back with it, the client of the configuration and
     * the user it was made for included.
     */
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
     * §10.2: what is kept for a client this provider has to call back is kept sealed, and comes back as
     * the bytes it was.
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
     * §10.1: the approval is kept with the session it was given with and what that session had proven,
     * which is what the tokens of the grant descend from.
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
     * §10.1: the page where a user answers reads what is waiting for them, oldest first, and nothing that
     * is waiting for somebody else.
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

    /**
     * A request that was answered, that was spent or that expired is waiting for nobody.
     */
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
     * §10.1: a spent record stays, so that its second presentation is told from an identifier nobody
     * issued.
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

    /**
     * An identifier nobody issued is found by nothing, as one of a client no longer registered is.
     */
    #[Test]
    public function anIdentifierThisProviderNeverAnsweredIsFoundByNothing(): void
    {
        // When / Then
        static::assertNull(self::records()->findByAuthRequestIdHash(DrawnSecret::digestOf('never-answered')));
    }

    private static function records(): BackchannelAuthenticationRecordRepositoryInterface
    {
        return self::service('test.heidi.backchannel_authentication_requests', BackchannelAuthenticationRecordRepositoryInterface::class);
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
