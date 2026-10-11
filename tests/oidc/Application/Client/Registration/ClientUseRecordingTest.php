<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\ClientUseRecording;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientStore;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Beffroi\Oidc\Domain\Event\ClientInUseInterface;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0009: the date a stored client carries of its last use, written from the two events that say
 * somebody is using it.
 */
final class ClientUseRecordingTest extends TestCase
{
    private const string CLIENT_ID = 'drawn-identifier';

    private Tenant $tenant;

    private InMemoryClientStore $clients;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientStore();
    }

    /**
     * The two things that mean somebody is using a client: an authorization granted for it, and a request it
     * made at the token endpoint.
     */
    /**
     * @param callable(Tenant, string, DateTimeImmutable): ClientInUseInterface $event
     */
    #[Test]
    #[DataProvider('provideUses')]
    public function aUseMovesTheDateOfTheLastOne(callable $event): void
    {
        // Given
        $this->register();

        // When
        $this->record($event($this->tenant, self::CLIENT_ID, Fixtures::now()->modify('+1 hour')));

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $this->clients->findRecord($this->tenant, self::CLIENT_ID)?->lastUsedAt);
    }

    /**
     * @return iterable<string, array{callable(Tenant, string, DateTimeImmutable): ClientInUseInterface}>
     */
    public static function provideUses(): iterable
    {
        yield 'an authorization granted for the client' => [self::authorizationCodeIssued(...)];

        yield 'a request the client made at the token endpoint' => [self::tokensIssued(...)];
    }

    /**
     * A request served for another client is not a use of this one.
     */
    #[Test]
    public function aUseOfAnotherClientLeavesThisOneAlone(): void
    {
        // Given
        $this->register();

        // When
        $this->record(self::tokensIssued($this->tenant, 'another-drawn-identifier', Fixtures::now()->modify('+1 hour')));

        // Then
        static::assertNull($this->clients->findRecord($this->tenant, self::CLIENT_ID)?->lastUsedAt);
    }

    /**
     * A client a deployment declared has no row, so there is nothing to write and nothing is written: it is
     * never deleted for want of use, and nothing here has to know that.
     */
    #[Test]
    public function aClientWithNoRowIsRecordedNowhere(): void
    {
        // When
        $this->record(self::tokensIssued($this->tenant, 'oidc-demo', Fixtures::now()));

        // Then
        static::assertSame([], $this->clients->records);
    }

    private function register(): void
    {
        $this->clients->save(new ClientRecord(
            Uuid::v7(),
            $this->tenant,
            self::CLIENT_ID,
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            null,
            DrawnSecret::digestOf(Secrets::draw()),
            Fixtures::now(),
        ));
    }

    private function record(ClientInUseInterface $event): void
    {
        new ClientUseRecording($this->clients)->record($event);
    }

    private static function authorizationCodeIssued(Tenant $tenant, string $clientId, DateTimeImmutable $at): ClientInUseInterface
    {
        return new AuthorizationCodeIssued(
            $at,
            $tenant,
            $clientId,
            Fixtures::user()->subject,
            Uuid::v7(),
            Uuid::v7(),
            DrawnSecret::digestOf(Secrets::draw()),
            new Scopes([Scope::openid()]),
            $at->modify('+60 seconds'),
            Fixtures::context($at),
        );
    }

    private static function tokensIssued(Tenant $tenant, string $clientId, DateTimeImmutable $at): ClientInUseInterface
    {
        return new TokensIssued(
            $at,
            $tenant,
            new GrantTypeName('authorization_code'),
            Uuid::v7(),
            $clientId,
            Fixtures::user()->subject,
            null,
            new Scopes([Scope::openid()]),
            $at->modify('+300 seconds'),
            true,
            null,
            null,
            null,
            null,
            'jwt',
            Fixtures::context($at),
        );
    }
}
