<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use Heidi\Oidc\Application\Client\Registration\ClientConfigurationAccess;
use Heidi\Oidc\Application\Client\Registration\ClientConfigurationRemoval;
use Heidi\Oidc\Application\Client\Registration\RegisteredClientRemoval;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Event\RegisteredClientDeleted;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\UnauthorizedClientConfigurationException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7592 §2.3: a client deletes itself, and what is left of it is nothing.
 */
final class ClientConfigurationRemovalTest extends TestCase
{
    private const string TOKEN = 'a-value-the-provider-handed-that-client';

    private const string CLIENT_ID = 'drawn-identifier';

    private Tenant $tenant;

    private InMemoryClientStore $clients;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientStore();
        $this->events = new RecordingEventDispatcher();
        $this->clients->save(new ClientRecord(
            Uuid::v7(),
            $this->tenant,
            self::CLIENT_ID,
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            null,
            DrawnSecret::digestOf(self::TOKEN),
            Fixtures::now(),
        ));
    }

    #[Test]
    public function theClientIsGoneFromTheStore(): void
    {
        // When
        $this->remove('Bearer ' . self::TOKEN);

        // Then
        static::assertNull($this->clients->findRecord($this->tenant, self::CLIENT_ID));
    }

    /**
     * One event for one thing happening: the timed step that drops a client nobody uses emits the same one.
     */
    #[Test]
    public function theDeletionEmitsTheOneEventAClientGoingAwayEmits(): void
    {
        // When
        $this->remove('Bearer ' . self::TOKEN);

        // Then
        $events = $this->events->of(RegisteredClientDeleted::class);
        static::assertCount(1, $events);
        static::assertSame(self::CLIENT_ID, $events[0]->clientId);
    }

    /**
     * The token that read the client reads nothing afterwards, which is what a client that comes back sees.
     */
    #[Test]
    public function theTokenThatDeletedTheClientReadsNothingAfterwards(): void
    {
        // Given
        $this->remove('Bearer ' . self::TOKEN);

        // Then
        $this->expectException(UnauthorizedClientConfigurationException::class);

        // When
        $this->remove('Bearer ' . self::TOKEN);
    }

    #[Test]
    public function aRequestThatReadsNoClientRemovesNothing(): void
    {
        // When
        try {
            $this->remove(null);
        } catch (UnauthorizedClientConfigurationException) {
        }

        // Then
        static::assertNotNull($this->clients->findRecord($this->tenant, self::CLIENT_ID));
    }

    #[Test]
    public function aRequestThatReadsNoClientEmitsNothing(): void
    {
        // When
        try {
            $this->remove(null);
        } catch (UnauthorizedClientConfigurationException) {
        }

        // Then
        static::assertSame([], $this->events->events);
    }

    private function remove(?string $header): void
    {
        new ClientConfigurationRemoval(
            new ClientConfigurationAccess($this->clients),
            new RegisteredClientRemoval($this->clients, $this->events),
        )->remove($this->tenant, self::CLIENT_ID, $header, Fixtures::context());
    }
}
