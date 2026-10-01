<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use Heidi\Bundle\Tests\Fixture\EnrichTheProvenance;
use Heidi\Bundle\Tests\Fixture\EnrichTheProvenanceHandler;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Ciba\BindingMessage;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Heidi\Oidc\Domain\Device\UserCode;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Heidi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use function is_resource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function stream_get_contents;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The provenance of a request, one sealed column each, on the three tables that hold one (decisions 0011
 * and 0018).
 *
 * It was an embeddable of five columns mapped four times, and an embeddable cannot seal: it fixes the type
 * of each of its fields once for the whole model, so the same field could not carry the type of each of
 * the three tables, and the family a sealed type belongs to is its table. One column and one JSON document
 * now, which is what this bundle already does with every value object a column holds whole.
 *
 * **What this spike had to get right here** is the write path: the enrichment of a provenance is meant to
 * be asynchronous, so a column of it is written from a handler of the bus and not from a request, and a
 * sealed column written with no ambient tenant is refused rather than written under a wrong scope. The
 * enrichment itself does not exist, the port being there with a bridge that locates nothing and nobody
 * calling it, so what is played here is a message of this suite consumed by the bus with no request in
 * sight.
 */
final class RequestContextColumnsTest extends DatabaseTestCase
{
    private const string IP_ADDRESS = '203.0.113.10';

    private const string USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0';

    private const string BINDING_MESSAGE = 'Payment of 42 euros';

    /**
     * Read back as the domain wrote it: the provenance comes back as the object it was, the encrypted type
     * decorating the type of the column and the type holding the whole of it.
     */
    #[Test]
    public function aSessionIsReadBackWithBothOfItsProvenances(): void
    {
        // Given
        $saved = self::session(self::user());
        self::reload();

        // When
        $read = self::sessions()->find($saved->id);

        // Then
        static::assertInstanceOf(AuthenticationSession::class, $read);
        static::assertSame(self::IP_ADDRESS, $read->createdFrom->ipAddress);
        static::assertSame(self::USER_AGENT, $read->createdFrom->userAgent);
        static::assertSame(self::IP_ADDRESS, $read->lastSeenFrom->ipAddress);
        static::assertSame(
            $saved->createdFrom->receivedAt->format('Y-m-d H:i:s'),
            $read->createdFrom->receivedAt->format('Y-m-d H:i:s'),
        );
    }

    /**
     * The two provenances of a session are independent columns, as they were two groups of columns: what a
     * session is seen again from does not touch what it was created from.
     */
    #[Test]
    public function aSessionSeenAgainKeepsTheProvenanceItWasCreatedFrom(): void
    {
        // Given
        $session = self::session(self::user());
        $createdFrom = $session->createdFrom;

        // When
        $session->touch(new RequestContext(self::now()->modify('+1 hour'), '198.51.100.7', 'curl/8.5.0'), $session->expiresAt);
        self::sessions()->save($session);
        self::reload();

        // Then
        $read = self::sessions()->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $read);
        static::assertSame('198.51.100.7', $read->lastSeenFrom->ipAddress);
        static::assertSame($createdFrom->ipAddress, $read->createdFrom->ipAddress);
        static::assertSame($createdFrom->userAgent, $read->createdFrom->userAgent);
    }

    /**
     * The write path the enrichment will take, and the reason this issue belongs to this spike: a handler
     * of the bus, with no request anywhere, writing a sealed column. It is written under the scope of its
     * tenant, which `TenantProvider` answers from the configuration and not from a request, and read back.
     */
    #[Test]
    public function anEnrichmentWrittenFromTheBusReachesTheScopeOfItsTenant(): void
    {
        // Given
        $session = self::session(self::user());
        self::reload();

        // When
        self::service('test.heidi.command_bus', MessageBusInterface::class)->dispatch(new EnrichTheProvenance($session->id));
        self::reload();

        // Then
        $read = self::sessions()->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $read);
        static::assertSame(EnrichTheProvenanceHandler::CITY, $read->lastSeenFrom->location?->city);
        static::assertSame(EnrichTheProvenanceHandler::BROWSER, $read->lastSeenFrom->device?->browser);
        static::assertNull($read->createdFrom->location);
    }

    /**
     * And what the row holds then, which is the point of sealing it: the enrichment a handler wrote is not
     * in the clear either.
     */
    #[Test]
    public function theRowHoldsNothingOfTheEnrichmentAHandlerWrote(): void
    {
        // Given
        $session = self::session(self::user());
        self::service('test.heidi.command_bus', MessageBusInterface::class)->dispatch(new EnrichTheProvenance($session->id));

        // When
        $stored = self::column('heidi_authentication_session', 'last_seen_from');

        // Then
        static::assertStringNotContainsString(EnrichTheProvenanceHandler::CITY, $stored);
        static::assertStringNotContainsString(EnrichTheProvenanceHandler::BROWSER, $stored);
    }

    /**
     * Column by column over the four provenances of the schema: a column that stopped sealing fails on its
     * own line.
     *
     * @param list<string> $plaintexts
     */
    #[Test]
    #[DataProvider('provideProvenances')]
    public function theRowHoldsNothingOfItsProvenance(string $table, string $column, array $plaintexts): void
    {
        // Given
        self::rows();

        // When
        $stored = self::column($table, $column);

        // Then
        foreach ($plaintexts as $plaintext) {
            static::assertStringNotContainsString(
                $plaintext,
                $stored,
                sprintf('%s.%s holds "%s" in the clear.', $table, $column, $plaintext),
            );
        }
    }

    /**
     * @return iterable<string, array{string, string, list<string>}>
     */
    public static function provideProvenances(): iterable
    {
        $provenance = [self::IP_ADDRESS, self::USER_AGENT];

        yield 'the session was created from' => ['heidi_authentication_session', 'created_from', $provenance];
        yield 'the session was last seen from' => ['heidi_authentication_session', 'last_seen_from', $provenance];
        yield 'the device authorization was requested from' => ['heidi_device_authorization_request', 'requested_from', $provenance];
        yield 'the backchannel authentication was requested from' => ['heidi_backchannel_authentication_request', 'requested_from', $provenance];
        yield 'the sentence a person reads on the device' => [
            'heidi_backchannel_authentication_request',
            'binding_message',
            [self::BINDING_MESSAGE],
        ];
    }

    /**
     * One row of each of the three tables, written through the repositories a request writes them with.
     */
    private static function rows(): void
    {
        $user = self::user();
        $client = self::client();
        self::session($user);
        self::service('test.heidi.device_authorization_requests', DeviceAuthorizationRecordRepositoryInterface::class)
            ->save(
                new DeviceAuthorizationRecord(
                    DrawnSecret::digestOf('a-device-code'),
                    UserCode::hashOf('ZXWVTSRQ'),
                    Uuid::v7(),
                    $client,
                    new Scopes([new Scope('openid')]),
                    new ResourceIndicators([new ResourceIndicator('https://cal.example.com/')]),
                    self::context(),
                    self::now(),
                    self::now()->modify('+10 minutes'),
                ),
            );
        self::service('test.heidi.backchannel_authentication_requests', BackchannelAuthenticationRecordRepositoryInterface::class)
            ->save(
                new BackchannelAuthenticationRecord(
                    DrawnSecret::digestOf('an-auth-request-id'),
                    Uuid::v7(),
                    $client,
                    $user,
                    new Scopes([new Scope('openid')]),
                    new ResourceIndicators([new ResourceIndicator('https://cal.example.com/')]),
                    new BindingMessage(self::BINDING_MESSAGE),
                    ['phr'],
                    null,
                    null,
                    self::context(),
                    self::now(),
                    self::now()->modify('+5 minutes'),
                ),
            );
    }

    /**
     * One column of the one row of a table as the database holds it: nothing converts a type here, which is
     * the whole point of reading it this way.
     */
    private static function column(string $table, string $column): string
    {
        $rows = self::connection()->fetchFirstColumn(sprintf('SELECT %s FROM %s', $column, $table));
        static::assertCount(1, $rows);
        $value = $rows[0];

        if (is_resource($value)) {
            return (string) stream_get_contents($value);
        }
        static::assertIsString($value);

        return $value;
    }

    private static function sessions(): AuthenticationSessionRepositoryInterface
    {
        return self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
