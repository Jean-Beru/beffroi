<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Administration;

use Beffroi\Core\Application\Administration\Administrators;
use Beffroi\Core\Bridge\Configuration\ConfigurationAdministratorGroups;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Administration\AdministratorOfARequest;
use Beffroi\Oidc\Application\Grant\RecordedGrants;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Application\Token\PresentedAccessTokenParser;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationAdministrationResource;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAccessTokenRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\TokenBindingNotProvenException;
use Beffroi\Oidc\Tests\Fixture\AccessTokenShapes;
use Beffroi\Oidc\Tests\Fixture\Administrations;
use Beffroi\Oidc\Tests\Fixture\Bindings;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Jwts;
use Beffroi\Oidc\Tests\Fixture\Proofs;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use Closure;
use function sprintf;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Throwable;

/**
 * Decision 0038: a request to the administration API is let in for a token of this provider addressed to the API,
 * bound to a key the request proves again, descending from a session that satisfies phishing_resistant, for a person
 * who administers the tenant when the request is made, and refused otherwise as a refusal of its token.
 */
final class AdministratorOfARequestTest extends TestCase
{
    private const string PATH = '/tenant';

    /**
     * A proof is used once (RFC 9449 §11.1), so each one made here carries an identifier of its own.
     */
    private static int $proofs = 0;

    private Tenant $tenant;

    private InMemoryUserRepository $users;

    private Client $client;

    private InMemoryAuthenticationSessionRepository $sessions;

    private InMemoryAuthorizationCodeRepository $grants;

    private InMemoryGroupMembershipRepository $memberships;

    private GroupMembership $membership;

    private JwtAccessTokenIssuer $accessTokens;

    private AdministratorOfARequest $requests;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $administrator = Fixtures::user($this->tenant);
        $this->users = new InMemoryUserRepository();
        $this->users->save($administrator);
        $this->users->save(Fixtures::user($this->tenant, 'bob', 'bob-subject'));
        $this->client = Clients::public($this->tenant, resources: [new ResourceIndicator(Administrations::RESOURCE), new ResourceIndicator(Clients::CALENDAR)]);
        $this->memberships = new InMemoryGroupMembershipRepository();
        $group = new Group(Uuid::v7(), $this->tenant, Administrations::GROUP, GroupSource::Local, Fixtures::now());
        $this->membership = new GroupMembership(Uuid::v7(), $group, $administrator, GroupSource::Local, Fixtures::now());
        $this->memberships->save($this->membership);
        $this->sessions = new InMemoryAuthenticationSessionRepository();
        $this->grants = new InMemoryAuthorizationCodeRepository();
        $jwts = new Jwts($this->tenant);
        $this->accessTokens = new JwtAccessTokenIssuer(
            $jwts->signer,
            Subjects::publicKind(),
            Algorithms::all(),
            new SymfonyUuidGenerator(),
            Subjects::sealedPerson(),
        );
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $this->requests = new AdministratorOfARequest(
            new ConfigurationAdministrationResource($this->tenant->slug, Administrations::RESOURCE),
            new Administrators(new ConfigurationAdministratorGroups($this->tenant->slug, [Administrations::GROUP]), $this->memberships),
            new PresentedAccessTokenParser(Bindings::wired()),
            Proofs::verifier(),
            new AccessTokenInspector(
                AccessTokenShapes::verifier(
                    new JwtLibraryJwsVerifier($jwts->keys, Algorithms::all()),
                    $clients,
                    new InMemoryAccessTokenRepository(),
                    Subjects::publicKind(),
                ),
                $this->sessions,
                new RecordedGrants([$this->grants]),
                Subjects::personOfAToken($this->users),
            ),
            $this->sessions,
        );
    }

    #[Test]
    public function anAdministratorSignedInWithAPasskeyIsLetIn(): void
    {
        // Given
        $token = $this->token('alice', self::passkey(), true);

        // When
        $administrator = $this->requests->administratorOf($this->tenant, 'GET', self::PATH, 'DPoP ' . $token, Fixtures::context(), null, self::proof($token));

        // Then
        static::assertSame(['alice-subject', 'spa'], [$administrator->user->subject->value, $administrator->clientId]);
    }

    /**
     * @param Closure(self): array{string|null, string|null} $request the Authorization header and the DPoP proof
     * @param class-string<Throwable> $refusal
     */
    #[Test]
    #[DataProvider('provideRequestsTheApiRefuses')]
    public function aRequestThatIsNotAnAdministratorsIsRefusedAsItsToken(Closure $request, string $refusal): void
    {
        // Given
        [$authorization, $proof] = $request($this);

        // Then
        $this->expectException($refusal);

        // When
        $this->requests->administratorOf($this->tenant, 'GET', self::PATH, $authorization, Fixtures::context(), null, $proof);
    }

    /**
     * @return iterable<string, array{Closure(self): array{string|null, string|null}, class-string<Throwable>}>
     */
    public static function provideRequestsTheApiRefuses(): iterable
    {
        yield 'no token (RFC 6750 §3.1)' => [
            static fn (self $test): array => [null, null],
            MissingBearerTokenException::class,
        ];
        yield 'a token bound to no key (RFC 9449 §6)' => [
            static fn (self $test): array => ['Bearer ' . $test->token('alice', self::passkey(), false), null],
            InvalidTokenException::class,
        ];
        yield 'a bound token presented as a bearer token (RFC 9449 §7.1)' => [
            static fn (self $test): array => ['Bearer ' . $test->token('alice', self::passkey(), true), null],
            TokenBindingNotProvenException::class,
        ];
        yield 'a bound token without the proof of its key' => [
            static fn (self $test): array => ['DPoP ' . $test->token('alice', self::passkey(), true), null],
            TokenBindingNotProvenException::class,
        ];
        yield 'a token addressed to another resource (RFC 8707 §2)' => [
            static function (self $test): array {
                $token = $test->token('alice', self::passkey(), true, Clients::CALENDAR);

                return [
                    'DPoP ' . $token,
                    self::proof($token),
                ];
            },
            InvalidTokenException::class,
        ];
        yield 'a token of a session that proved a password alone' => [
            static function (self $test): array {
                $token = $test->token('alice', self::password(), true);

                return [
                    'DPoP ' . $token,
                    self::proof($token),
                ];
            },
            InvalidTokenException::class,
        ];
        yield 'a token of a person who does not administer the tenant' => [
            static function (self $test): array {
                $token = $test->token('bob', self::passkey(), true);

                return [
                    'DPoP ' . $token,
                    self::proof($token),
                ];
            },
            InvalidTokenException::class,
        ];
        yield 'a token of a person taken out of the group since it was issued' => [
            static function (self $test): array {
                $token = $test->token('alice', self::passkey(), true);
                $test->leaveTheGroup();

                return [
                    'DPoP ' . $token,
                    self::proof($token),
                ];
            },
            InvalidTokenException::class,
        ];
    }

    /**
     * A tenant whose deployment names no administration API has none, and no token opens it.
     */
    #[Test]
    public function noTokenOpensTheApiOfATenantThatNamesNone(): void
    {
        // Given
        $token = $this->token('alice', self::passkey(), true);
        $tenant = Fixtures::tenant('another');

        // Then
        $this->expectException(InvalidTokenException::class);

        // When
        $this->requests->administratorOf($tenant, 'GET', self::PATH, 'DPoP ' . $token, Fixtures::context(), null, self::proof($token));
    }

    /**
     * An access token of a sign-in by the person of that username, with the proofs given, addressed to the resource
     * given and bound to the key of Proofs when it is bound.
     */
    public function token(string $username, AuthenticationProofs $proofs, bool $bound, string $resource = Administrations::RESOURCE): string
    {
        $user = $this->users->findByUsername($this->tenant, $username) ?? static::fail(sprintf('Nobody is named "%s" here.', $username));
        $session = Fixtures::session($user, proofs: $proofs);
        $this->sessions->save($session);
        $code = Tokens::code('the-code', $this->client, $session, Fixtures::now(), resources: ResourceIndicators::of([$resource]));
        $this->grants->save($code);
        $authorization = UserAuthorization::fromAuthorizationCode(
            Grants::authorizationCode(),
            $code,
            $bound ? Proofs::thumbprintOf(Proofs::key()) : null,
        );

        return Tokens::accessToken($this->accessTokens, $authorization, Fixtures::now())->value;
    }

    /**
     * The administrator taken out of the group the tenant names, as a directory that removes them would.
     */
    public function leaveTheGroup(): void
    {
        $this->memberships->remove($this->membership);
    }

    private static function proof(string $token): string
    {
        return Proofs::proof('GET', Administrations::RESOURCE . self::PATH, Fixtures::now(), $token, [
            'jti' => 'administration-' . self::$proofs++,
        ]);
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
