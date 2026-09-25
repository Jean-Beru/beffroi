<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Heidi\Oidc\Domain\Device\UserCode;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;

/**
 * RFC 8628 §3.2, architecture §5.3: a device authorization request keyed by the hash of the code its client
 * polls with, found again by the code its user types, with the approval it carries; a spent record stays.
 */
final class DoctrineDeviceAuthorizationRecordRepositoryTest extends DatabaseTestCase
{
    private const string USER_CODE = 'BCDFGHJK';

    /**
     * RFC 8628 §3.5: the claim is one conditional statement, so a second caller is told it lost, and it holds
     * the date the first one wrote.
     */
    #[Test]
    public function onlyTheFirstCallerSpendsTheDeviceCode(): void
    {
        // Given
        $deviceCode = Secrets::draw();
        self::records()->save(self::record($deviceCode, self::client('appliance-app')));
        self::reload();
        $record = self::records()->findByDeviceCodeHash(DrawnSecret::digestOf($deviceCode)) ?? static::fail('The record was not stored.');

        // When
        $first = self::records()->consume($record, self::now());
        $second = self::records()->consume($record, self::now()->modify('+1 second'));

        // Then
        static::assertTrue($first);
        static::assertFalse($second);
        static::assertEquals(self::now(), $record->usedAt);
    }

    /**
     * What the token endpoint needs of a record comes back with it, the client of the configuration included.
     */
    #[Test]
    public function aRecordComesBackWithWhatTheGrantNeeds(): void
    {
        // Given
        $deviceCode = Secrets::draw();
        self::records()->save(self::record($deviceCode, self::client('appliance-app')));
        self::reload();

        // When
        $found = self::records()->findByDeviceCodeHash(DrawnSecret::digestOf($deviceCode)) ?? static::fail('The record was not stored.');

        // Then
        static::assertSame(DrawnSecret::digestOf($deviceCode), $found->deviceCodeHash);
        static::assertSame(UserCode::hashOf(self::USER_CODE), $found->userCodeHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('appliance-app', $found->clientId);
        static::assertSame('appliance-app', $found->client->registration->clientId);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $found->scopes->all);
        static::assertEquals([new ResourceIndicator('https://cal.example.com/')], $found->resources?->all);
        static::assertSame('203.0.113.10', $found->requestedFrom->ipAddress);
        static::assertSame(5, $found->interval);
        static::assertEquals(self::now()->modify('+10 minutes'), $found->expiresAt);
        static::assertFalse($found->isAnswered());
        static::assertFalse($found->isUsed());
        static::assertNull($found->session);
        static::assertNull($found->authentication);
    }

    /**
     * RFC 8628 §3.3: the approval is kept with the session it was given with and what that session had
     * proven, which is what the tokens of the grant descend from.
     */
    #[Test]
    public function anApprovalComesBackWithItsSessionAndWhatItHadProven(): void
    {
        // Given
        $deviceCode = Secrets::draw();
        $session = self::session(self::user());
        $record = self::record($deviceCode, self::client('appliance-app'));
        $record->approve($session, new AuthenticationSnapshot(self::now(), ['pwd'], '1'), self::now()->modify('+30 seconds'));
        self::records()->save($record);
        self::reload();

        // When
        $found = self::records()->findByDeviceCodeHash(DrawnSecret::digestOf($deviceCode)) ?? static::fail('The record was not stored.');

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
     * The page a user types on looks a record up by the code they typed.
     */
    #[Test]
    public function aRecordIsFoundByTheCodeItsUserTypes(): void
    {
        // Given
        $deviceCode = Secrets::draw();
        self::records()->save(self::record($deviceCode, self::client('appliance-app')));
        self::reload();

        // When
        $found = self::records()->findByUserCodeHash(UserCode::hashOf(self::USER_CODE));

        // Then
        static::assertSame(DrawnSecret::digestOf($deviceCode), $found?->deviceCodeHash);
    }

    /**
     * RFC 8628 §3.5: a refusal is kept, so that the client is told the same thing at every poll after it.
     */
    #[Test]
    public function aRefusalIsKept(): void
    {
        // Given
        $deviceCode = Secrets::draw();
        $record = self::record($deviceCode, self::client('appliance-app'));
        $record->deny(self::now()->modify('+30 seconds'));
        self::records()->save($record);
        self::reload();

        // When
        $found = self::records()->findByDeviceCodeHash(DrawnSecret::digestOf($deviceCode)) ?? static::fail('The record was not stored.');

        // Then
        static::assertTrue($found->isDenied());
        static::assertEquals(self::now()->modify('+30 seconds'), $found->deniedAt);
    }

    /**
     * RFC 8628 §3.5: a spent record stays, so that its second presentation is told from a code nobody issued.
     */
    #[Test]
    public function aSpentRecordStaysSpent(): void
    {
        // Given
        $deviceCode = Secrets::draw();
        $record = self::record($deviceCode, self::client('appliance-app'));
        self::records()->save($record);
        $record->consume(self::now()->modify('+90 seconds'));
        self::records()->save($record);
        self::reload();

        // When
        $found = self::records()->findByDeviceCodeHash(DrawnSecret::digestOf($deviceCode)) ?? static::fail('The record was not stored.');

        // Then
        static::assertTrue($found->isUsed());
        static::assertEquals(self::now()->modify('+90 seconds'), $found->usedAt);
    }

    /**
     * A code nobody issued is found by nothing, as a code of a client no longer registered is.
     */
    #[Test]
    public function aCodeThisProviderNeverAnsweredIsFoundByNothing(): void
    {
        // When / Then
        static::assertNull(self::records()->findByDeviceCodeHash(DrawnSecret::digestOf('never-answered')));
        static::assertNull(self::records()->findByUserCodeHash(UserCode::hashOf('ZXWVTSRQ')));
    }

    private static function records(): DeviceAuthorizationRecordRepositoryInterface
    {
        return self::service('test.heidi.device_authorization_requests', DeviceAuthorizationRecordRepositoryInterface::class);
    }

    private static function record(string $deviceCode, Client $client): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord(
            DrawnSecret::digestOf($deviceCode),
            UserCode::hashOf(self::USER_CODE),
            $client,
            new Scopes([new Scope('openid'), new Scope('profile')]),
            new ResourceIndicators([new ResourceIndicator('https://cal.example.com/')]),
            self::context(),
            self::now(),
            self::now()->modify('+10 minutes'),
        );
    }
}
