<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Consent;

use function array_map;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.3: a consent binds a user and a client of the same tenant to a set of scopes, and
 * covers a request when every requested scope is in that set.
 */
final class ConsentTest extends TestCase
{
    private User $user;

    private Client $client;

    private Consent $consent;

    protected function setUp(): void
    {
        $this->user = Fixtures::user();
        $this->client = Clients::public($this->user->tenant);
        $this->consent = new Consent(Uuid::v7(), $this->user, $this->client, [new Scope('openid'), new Scope('profile'), new Scope('openid')], Fixtures::now());
    }

    #[Test]
    public function itBindsTheUserAndTheClientToASetOfScopesEachOnce(): void
    {
        // When / Then
        static::assertSame($this->user->tenant, $this->consent->tenant);
        static::assertSame($this->client->clientId, $this->consent->clientId);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $this->consent->scopes);
    }

    #[Test]
    public function aNewConsentIsActive(): void
    {
        // When / Then
        static::assertTrue($this->consent->isActive());
        static::assertNull($this->consent->revokedAt);
    }

    /**
     * @param list<Scope> $requested
     */
    #[Test]
    #[DataProvider('provideRequestedScopes')]
    public function itCoversARequestWhoseScopesWereAllGranted(array $requested, bool $covered): void
    {
        // When / Then
        static::assertSame($covered, $this->consent->covers($requested));
    }

    /**
     * @return iterable<string, array{list<Scope>, bool}>
     */
    public static function provideRequestedScopes(): iterable
    {
        yield 'one granted scope' => [[new Scope('openid')], true];
        yield 'all granted scopes in another order' => [[new Scope('profile'), new Scope('openid')], true];
        yield 'nothing' => [[], true];
        yield 'a scope never granted' => [[new Scope('openid'), new Scope('email')], false];
    }

    #[Test]
    public function itKnowsTheScopesItGranted(): void
    {
        // When / Then
        static::assertTrue($this->consent->hasScope(new Scope('profile')));
        static::assertFalse($this->consent->hasScope(new Scope('email')));
    }

    #[Test]
    public function itIsForItsUserAndAnyClientOfTheSameRegistration(): void
    {
        // When / Then
        static::assertTrue($this->consent->isFor($this->user, $this->client));
        static::assertTrue($this->consent->isFor($this->user, Clients::public($this->user->tenant)));
    }

    #[Test]
    public function itIsNotForAnotherUser(): void
    {
        // When / Then
        static::assertFalse($this->consent->isFor(Fixtures::user($this->user->tenant, 'bob', 'bob-subject'), $this->client));
    }

    #[Test]
    public function itIsNotForAnotherClient(): void
    {
        // When / Then
        static::assertFalse($this->consent->isFor($this->user, Clients::public($this->user->tenant, 'another-app')));
    }

    #[Test]
    public function revokingDatesTheRevocation(): void
    {
        // Given
        $revokedAt = Fixtures::now()->modify('+1 day');

        // When
        $this->consent->revoke($revokedAt);

        // Then
        static::assertFalse($this->consent->isActive());
        static::assertEquals($revokedAt, $this->consent->revokedAt);
    }

    /**
     * The first revocation wins.
     */
    #[Test]
    public function itIsRevokedOnce(): void
    {
        // Given
        $first = Fixtures::now()->modify('+1 day');
        $this->consent->revoke($first);

        // When
        $this->consent->revoke(Fixtures::now()->modify('+2 days'));

        // Then
        static::assertEquals($first, $this->consent->revokedAt);
    }

    #[Test]
    public function extendingItGivesANewConsentWithTheScopesOfBothEachOnce(): void
    {
        // Given
        $later = Fixtures::now()->modify('+1 day');

        // When
        $extended = $this->consent->extendedWith([Scope::openid(), new Scope('email')], Uuid::v7(), $later);

        // Then
        static::assertSame(['openid', 'profile', 'email'], array_map(strval(...), $extended->scopes));
        static::assertSame($this->consent->user, $extended->user);
        static::assertSame($this->consent->client, $extended->client);
        static::assertEquals($later, $extended->grantedAt);
        static::assertTrue($extended->isActive());
        static::assertFalse($extended->id->equals($this->consent->id));
    }

    #[Test]
    public function extendingItRevokesItAtThatMoment(): void
    {
        // Given
        $later = Fixtures::now()->modify('+1 day');

        // When
        $this->consent->extendedWith([new Scope('email')], Uuid::v7(), $later);

        // Then
        static::assertFalse($this->consent->isActive());
        static::assertEquals($later, $this->consent->revokedAt);
    }

    #[Test]
    public function extendingItWithNothingNewStillSupersedesIt(): void
    {
        // When
        $extended = $this->consent->extendedWith([Scope::openid()], Uuid::v7(), Fixtures::now()->modify('+1 day'));

        // Then
        static::assertSame(['openid', 'profile'], array_map(strval(...), $extended->scopes));
        static::assertFalse($this->consent->isActive());
    }

    #[Test]
    public function itRefusesAClientOfAnotherTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Consent(Uuid::v7(), $this->user, Clients::public(Fixtures::tenant('other', 'https://id.other.example')), [new Scope('openid')], Fixtures::now());
    }

    #[Test]
    public function itRefusesAnEmptyScopeSet(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Consent(Uuid::v7(), $this->user, $this->client, [], Fixtures::now());
    }
}
