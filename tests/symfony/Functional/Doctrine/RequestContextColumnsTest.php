<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Doctrine\DBAL\Connection;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use App\Tests\Symfony\Fixture\EnrichTheProvenance;
use App\Tests\Symfony\Fixture\EnrichTheProvenanceHandler;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Messenger\MessageBusInterface;

final class RequestContextColumnsTest extends DatabaseTestCase
{
    private const string IP_ADDRESS = SealedRows::IP_ADDRESS;

    private const string USER_AGENT = SealedRows::USER_AGENT;

    private const string BINDING_MESSAGE = SealedRows::VALUES['beffroi_backchannel_authentication_request']['binding_message'];

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

    #[Test]
    public function anEnrichmentWrittenFromTheBusReachesTheScopeOfItsTenant(): void
    {
        // Given
        $session = self::session(self::user());
        self::reload();

        // When
        self::service('test.beffroi.command_bus', MessageBusInterface::class)->dispatch(new EnrichTheProvenance($session->id));
        self::reload();

        // Then
        $read = self::sessions()->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $read);
        static::assertSame(EnrichTheProvenanceHandler::CITY, $read->lastSeenFrom->location?->city);
        static::assertSame(EnrichTheProvenanceHandler::BROWSER, $read->lastSeenFrom->device?->browser);
        static::assertNull($read->createdFrom->location);
    }

    #[Test]
    public function theRowHoldsNothingOfTheEnrichmentAHandlerWrote(): void
    {
        // Given
        $session = self::session(self::user());
        self::service('test.beffroi.command_bus', MessageBusInterface::class)->dispatch(new EnrichTheProvenance($session->id));

        // When
        $stored = self::column('beffroi_authentication_session', 'last_seen_from');

        // Then
        static::assertStringNotContainsString(EnrichTheProvenanceHandler::CITY, $stored);
        static::assertStringNotContainsString(EnrichTheProvenanceHandler::BROWSER, $stored);
    }

    /**
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

        yield 'the session was created from' => ['beffroi_authentication_session', 'created_from', $provenance];
        yield 'the session was last seen from' => ['beffroi_authentication_session', 'last_seen_from', $provenance];
        yield 'the device authorization was requested from' => ['beffroi_device_authorization_request', 'requested_from', $provenance];
        yield 'the backchannel authentication was requested from' => ['beffroi_backchannel_authentication_request', 'requested_from', $provenance];
        yield 'the sentence a person reads on the device' => [
            'beffroi_backchannel_authentication_request',
            'binding_message',
            [self::BINDING_MESSAGE],
        ];
    }

    private static function rows(): void
    {
        $fixture = self::fixture();
        $user = self::user();
        $client = self::client();
        self::session($user);
        $fixture->deviceRequest($client);
        $fixture->backchannelRequest($client, $user);
    }

    private static function fixture(): SealedRows
    {
        return new SealedRows(self::getContainer(), self::tenant(), self::now());
    }

    private static function column(string $table, string $column): string
    {
        $rows = RawRows::of(self::connection(), $table, [$column]);
        static::assertCount(1, $rows);

        return $rows[0][$column] ?? static::fail(sprintf('%s.%s holds nothing.', $table, $column));
    }

    private static function sessions(): AuthenticationSessionRepositoryInterface
    {
        return self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
