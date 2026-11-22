<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Consent;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use function array_column;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.3
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
        $this->consent = new Consent(
            Uuid::v7(),
            $this->user,
            $this->client,
            new Scopes([new Scope('openid'), new Scope('profile'), new Scope('openid')]),
            Fixtures::now(),
        );
    }

    #[Test]
    public function itBindsTheUserAndTheClientToASetOfScopesEachOnce(): void
    {
        // When / Then
        static::assertSame($this->user->tenant, $this->consent->tenant);
        static::assertSame($this->client->registration->clientId, $this->consent->clientId);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $this->consent->scopes->all);
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
        static::assertSame($covered, $this->consent->scopes->covers(new Scopes($requested)));
    }

    /**
     * @return iterable<string, array{list<Scope>, bool}>
     */
    public static function provideRequestedScopes(): iterable
    {
        yield 'one granted scope' => [[new Scope('openid')], true];
        yield 'all granted scopes in another order' => [[new Scope('profile'), new Scope('openid')], true];
        yield 'a scope never granted' => [[new Scope('openid'), new Scope('email')], false];
    }

    #[Test]
    public function itKnowsTheScopesItGranted(): void
    {
        // When / Then
        static::assertTrue($this->consent->scopes->has(new Scope('profile')));
        static::assertFalse($this->consent->scopes->has(new Scope('email')));
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
        $extended = $this->consent->extendedWith(new Scopes([Scope::openid(), new Scope('email')]), null, new ClaimNames(), Uuid::v7(), $later);

        // Then
        static::assertSame(['openid', 'profile', 'email'], $extended->scopes->values());
        static::assertSame($this->consent->user, $extended->user);
        static::assertSame($this->consent->client, $extended->client);
        static::assertEquals($later, $extended->grantedAt);
        static::assertTrue($extended->isActive());
        static::assertFalse($extended->id->equals($this->consent->id));
    }

    /**
     * RFC 9396 §2
     */
    #[Test]
    public function aConsentCarriesTheAuthorizationDetailsItWasGiven(): void
    {
        // Given
        $details = AuthorizationDetailTypes::details();

        // When
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([Scope::openid()]), Fixtures::now(), $details);

        // Then
        static::assertSame($details, $consent->authorizationDetails);
        static::assertNull($this->consent->authorizationDetails);
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function extendingItGivesANewConsentWithTheAuthorizationDetailsOfBothEachOnce(): void
    {
        // Given
        $consent = new Consent(
            Uuid::v7(),
            $this->user,
            $this->client,
            new Scopes([Scope::openid()]),
            Fixtures::now(),
            AuthorizationDetailTypes::details('acct-4711'),
        );

        // When
        $extended = $consent->extendedWith(
            new Scopes([Scope::openid()]),
            new AuthorizationDetails([AuthorizationDetailTypes::detail('acct-4711'), AuthorizationDetailTypes::detail('acct-0815')]),
            new ClaimNames(),
            Uuid::v7(),
            Fixtures::now()->modify('+1 day'),
        );

        // Then
        static::assertSame(
            ['acct-4711', 'acct-0815'],
            array_column($extended->authorizationDetails?->toClaim() ?? [], 'account'),
        );
    }

    #[Test]
    public function extendingItWithNoDetailKeepsTheOnesItCarries(): void
    {
        // Given
        $consent = new Consent(
            Uuid::v7(),
            $this->user,
            $this->client,
            new Scopes([Scope::openid()]),
            Fixtures::now(),
            AuthorizationDetailTypes::details('acct-4711'),
        );

        // When
        $extended = $consent->extendedWith(new Scopes([Scope::openid()]), null, new ClaimNames(), Uuid::v7(), Fixtures::now()->modify('+1 day'));

        // Then
        static::assertTrue($extended->authorizationDetails?->equals(AuthorizationDetailTypes::details('acct-4711')));
    }

    /**
     * RFC 9396 §7
     */
    #[Test]
    public function aConsentCoversTheDetailsItCarriesAndNoOther(): void
    {
        // Given
        $consent = new Consent(
            Uuid::v7(),
            $this->user,
            $this->client,
            new Scopes([Scope::openid()]),
            Fixtures::now(),
            AuthorizationDetailTypes::details('acct-4711'),
        );

        // When / Then
        static::assertTrue($consent->coversAuthorizationDetails(null));
        static::assertTrue($consent->coversAuthorizationDetails(AuthorizationDetailTypes::details('acct-4711')));
        static::assertFalse($consent->coversAuthorizationDetails(AuthorizationDetailTypes::details('acct-0815')));
    }

    #[Test]
    public function aConsentCarryingNoDetailCoversNone(): void
    {
        // When / Then
        static::assertTrue($this->consent->coversAuthorizationDetails(null));
        static::assertFalse($this->consent->coversAuthorizationDetails(AuthorizationDetailTypes::details()));
    }

    /**
     * OIDC Core §5.5
     */
    #[Test]
    public function aConsentHoldsTheClaimsItWasGivenByName(): void
    {
        // Given
        $claims = new ClaimNames(['email', 'phone_number']);

        // When
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([Scope::openid()]), Fixtures::now(), null, $claims);

        // Then
        static::assertSame(['email', 'phone_number'], $consent->claims->all);
        static::assertTrue($this->consent->claims->isEmpty());
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function extendingItGivesANewConsentWithTheClaimsOfBothEachOnce(): void
    {
        // Given
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([Scope::openid()]), Fixtures::now(), null, new ClaimNames(['email']));

        // When
        $extended = $consent->extendedWith(
            new Scopes([Scope::openid()]),
            null,
            new ClaimNames(['phone_number', 'email']),
            Uuid::v7(),
            Fixtures::now()->modify('+1 day'),
        );

        // Then
        static::assertSame(['email', 'phone_number'], $extended->claims->all);
    }

    #[Test]
    public function extendingItWithNoClaimKeepsTheOnesItHolds(): void
    {
        // Given
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([Scope::openid()]), Fixtures::now(), null, new ClaimNames(['email']));

        // When
        $extended = $consent->extendedWith(new Scopes([new Scope('profile')]), null, new ClaimNames(), Uuid::v7(), Fixtures::now()->modify('+1 day'));

        // Then
        static::assertSame(['email'], $extended->claims->all);
    }

    /**
     * OIDC Core §3.1.2.4, §5.5
     *
     * @param list<string> $asked
     */
    #[Test]
    #[DataProvider('provideClaimsAskedForByName')]
    public function aConsentCoversTheClaimsItHoldsByNameAndNoOther(array $asked, bool $covered): void
    {
        // Given
        $consent = new Consent(Uuid::v7(), $this->user, $this->client, new Scopes([Scope::openid()]), Fixtures::now(), null, new ClaimNames(['email']));

        // When / Then
        static::assertSame($covered, $consent->coversClaims(new ClaimNames($asked)));
    }

    /**
     * @return iterable<string, array{list<string>, bool}>
     */
    public static function provideClaimsAskedForByName(): iterable
    {
        yield 'none' => [[], true];
        yield 'the one it holds' => [['email'], true];
        yield 'one it does not hold' => [['phone_number'], false];
        yield 'the one it holds and another' => [['email', 'phone_number'], false];
    }

    #[Test]
    public function extendingItRevokesItAtThatMoment(): void
    {
        // Given
        $later = Fixtures::now()->modify('+1 day');

        // When
        $this->consent->extendedWith(new Scopes([new Scope('email')]), null, new ClaimNames(), Uuid::v7(), $later);

        // Then
        static::assertFalse($this->consent->isActive());
        static::assertEquals($later, $this->consent->revokedAt);
    }

    #[Test]
    public function extendingItWithNothingNewStillSupersedesIt(): void
    {
        // When
        $extended = $this->consent->extendedWith(new Scopes([Scope::openid()]), null, new ClaimNames(), Uuid::v7(), Fixtures::now()->modify('+1 day'));

        // Then
        static::assertSame(['openid', 'profile'], $extended->scopes->values());
        static::assertFalse($this->consent->isActive());
    }

    #[Test]
    public function itRefusesAClientOfAnotherTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Consent(
            Uuid::v7(),
            $this->user,
            Clients::public(Fixtures::tenant('other', 'https://id.other.example')),
            new Scopes([new Scope('openid')]),
            Fixtures::now(),
        );
    }
}
