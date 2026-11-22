<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Administration;

use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Administration\AdministrationAudience;
use Beffroi\Oidc\Domain\Authorization\AuthenticationContextRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\AccessDeniedException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Tests\Fixture\Administrations;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Closure;
use function str_repeat;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: the audience of the administration API of a tenant is reserved to the administrators of that tenant,
 * signed in with a phishing-resistant proof, by a token bound to a key.
 */
final class AdministrationAudienceTest extends TestCase
{
    private User $administrator;

    private User $somebodyElse;

    private Client $client;

    private AdministrationAudience $audience;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $memberships = new InMemoryGroupMembershipRepository();
        $administrators = new Group(Uuid::v7(), $tenant, Administrations::GROUP, GroupSource::Local, Fixtures::now());
        $this->administrator = Fixtures::user($tenant, 'ada', 'ada-subject');
        $this->somebodyElse = Fixtures::user($tenant, 'bob', 'bob-subject');
        $memberships->save(new GroupMembership(Uuid::v7(), $administrators, $this->administrator, GroupSource::Local, Fixtures::now()));
        $this->client = Clients::public($tenant, resources: [new ResourceIndicator(Administrations::RESOURCE), new ResourceIndicator(Clients::CALENDAR)]);
        $this->audience = Administrations::of($tenant, $memberships);
    }

    /**
     * OIDC Core §5.5.1.1: "phr", essential, in place of the class the client asked for.
     */
    #[Test]
    public function aRequestForTheAdministrationApiDemandsAPhishingResistantProof(): void
    {
        // Given
        $request = Requests::authorization($this->client, acrValues: ['1'], resources: ResourceIndicators::of([Administrations::RESOURCE]));

        // When
        $asked = $this->audience->authenticationAskedBy($request);

        // Then
        static::assertEquals(new AuthenticationContextRequest(['phr'], true), $asked);
    }

    #[Test]
    public function aRequestForAnotherResourceAsksWhatItAskedFor(): void
    {
        // Given
        $request = Requests::authorization($this->client, acrValues: ['1'], resources: ResourceIndicators::of([Clients::CALENDAR]));

        // When
        $asked = $this->audience->authenticationAskedBy($request);

        // Then
        static::assertEquals(AuthenticationContextRequest::of($request), $asked);
    }

    /**
     * RFC 6749 §4.1.2.1.
     */
    #[Test]
    public function aPersonWhoDoesNotAdministerTheTenantIsDeniedTheAdministrationApi(): void
    {
        // Given
        $request = Requests::authorization($this->client, resources: ResourceIndicators::of([Administrations::RESOURCE]));

        // Then
        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionMessageIs('access_denied: The end user does not administer the tenant whose administration API the request names.');

        // When
        $this->audience->assertAdministeredBy($request, $this->somebodyElse);
    }

    #[Test]
    public function anAdministratorIsNotDeniedTheAdministrationApi(): void
    {
        // Given
        $request = Requests::authorization($this->client, resources: ResourceIndicators::of([Administrations::RESOURCE]));

        // Then
        $this->expectNotToPerformAssertions();

        // When
        $this->audience->assertAdministeredBy($request, $this->administrator);
    }

    #[Test]
    public function aPersonWhoDoesNotAdministerTheTenantIsNotDeniedAnotherResource(): void
    {
        // Given
        $request = Requests::authorization($this->client, resources: ResourceIndicators::of([Clients::CALENDAR]));

        // Then
        $this->expectNotToPerformAssertions();

        // When
        $this->audience->assertAdministeredBy($request, $this->somebodyElse);
    }

    #[Test]
    public function aTenantWhoseDeploymentNamesNoAdministrationApiReservesNothing(): void
    {
        // Given
        $request = Requests::authorization($this->client, resources: ResourceIndicators::of([Administrations::RESOURCE]));

        // Then
        $this->expectNotToPerformAssertions();

        // When
        Administrations::none()->assertAdministeredBy($request, $this->somebodyElse);
    }

    #[Test]
    public function anAdministratorSignedInWithAPasskeyGetsABoundTokenForTheAdministrationApi(): void
    {
        // Given
        $authorization = $this->authorization($this->administrator, self::passkey(), true);

        // Then
        $this->expectNotToPerformAssertions();

        // When
        $this->audience->assertMayBeAddressedBy($authorization);
    }

    /**
     * @param Closure(self): AuthorizationInterface $authorization
     */
    #[Test]
    #[DataProvider('provideAuthorizationsBelowTheReservation')]
    public function noOtherTokenIsAddressedToTheAdministrationApi(Closure $authorization): void
    {
        // Then
        $this->expectException(InvalidTargetException::class);
        $this->expectExceptionMessageIs('invalid_target: The requested resource is reserved to the administrators of the tenant (RFC 8707 section 2).');

        // When
        $this->audience->assertMayBeAddressedBy($authorization($this));
    }

    /**
     * @return iterable<string, array{Closure(self): AuthorizationInterface}>
     */
    public static function provideAuthorizationsBelowTheReservation(): iterable
    {
        yield 'a bearer token (RFC 9449 §6)' => [
            static fn (self $test): AuthorizationInterface => $test->authorization($test->administrator, self::passkey(), false),
        ];
        yield 'a session that proved a password alone' => [
            static fn (self $test): AuthorizationInterface => $test->authorization($test->administrator, self::password(), true),
        ];
        yield 'a person who does not administer the tenant' => [
            static fn (self $test): AuthorizationInterface => $test->authorization($test->somebodyElse, self::passkey(), true),
        ];
        yield 'a client acting for itself (RFC 6749 §4.4)' => [
            static fn (self $test): AuthorizationInterface => new ClientAuthorization(
                Grants::clientCredentials(),
                Uuid::v7(),
                Clients::service(
                    $test->client->tenant,
                    new FakePasswordHasher()->hash(Clients::SECRET),
                    resources: [new ResourceIndicator(Administrations::RESOURCE)],
                ),
                new Scopes([new Scope('invoices.read')]),
                ResourceIndicators::of([Administrations::RESOURCE]),
            ),
        ];
    }

    #[Test]
    public function aTokenForAnotherResourceIsNotHeldToTheReservation(): void
    {
        // Given
        $authorization = $this->authorization($this->somebodyElse, self::password(), false, Clients::CALENDAR);

        // Then
        $this->expectNotToPerformAssertions();

        // When
        $this->audience->assertMayBeAddressedBy($authorization);
    }

    private function authorization(User $user, AuthenticationProofs $proofs, bool $bound, string $resource = Administrations::RESOURCE): UserAuthorization
    {
        $session = Fixtures::session($user, proofs: $proofs);

        return UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            Tokens::code('the-code', $this->client, $session, Fixtures::now(), resources: ResourceIndicators::of([$resource])),
            $bound ? new KeyConfirmation(str_repeat('A', 43)) : null,
        );
    }

    private static function passkey(): AuthenticationProofs
    {
        return AuthenticationProofs::ofAll([new AuthenticationMethod('hwk'), new AuthenticationMethod('user')], Fixtures::now());
    }

    private static function password(): AuthenticationProofs
    {
        return AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now());
    }
}
