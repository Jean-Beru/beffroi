<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\ClaimsAskedByName;
use Beffroi\Oidc\Application\Claims\ServedClaims;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\InventedClaimsProvider;
use Beffroi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §5.5: a claim asked for by name is held to the scopes the client registered, a client registering
 * scopes and never claims (RFC 7591 §2), and to what the person agreed to (§3.1.2.4), and never further.
 */
final class ClaimsAskedByNameTest extends TestCase
{
    private Tenant $tenant;

    private ClaimsAskedByName $claims;

    /**
     * A client that registered "profile" and "email" and not "phone".
     */
    private Client $client;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->claims = new ClaimsAskedByName(new StandardClaimsProvider());
        $this->client = self::clientOf($this->tenant, ['openid', 'profile', 'email']);
    }

    /**
     * RFC 7591 §2, OIDC Core §5.5.1: a client is told the claims a scope it registered stands for, in each
     * member, what it asked of each kept; a claim no scope it registered stands for is not told, and asking
     * for it is no error.
     */
    #[Test]
    public function aClientMayBeToldTheClaimsAScopeItRegisteredStandsFor(): void
    {
        // Given
        $request = ClaimsRequest::fromJson('{"userinfo": {"email": {"essential": true}, "phone_number": null}, "id_token": {"name": null, "phone_number_verified": null}}');

        // When
        $grantable = $this->claims->grantable($this->client, $request);

        // Then
        static::assertEquals(['email' => new ClaimRequest(true)], $grantable?->userinfo);
        static::assertEquals(['name' => new ClaimRequest()], $grantable?->idToken);
    }

    /**
     * A request that asked for nothing by name is told nothing by name.
     */
    #[Test]
    public function aRequestThatAskedForNoClaimByNameStaysOne(): void
    {
        // When / Then
        static::assertNull($this->claims->grantable($this->client, null));
    }

    /**
     * OIDC Core §5.1: a claim of a deployment is held to the scope its class names, exactly as a claim of
     * §5.1 is held to its scope of §5.4.
     *
     * @param list<string> $registered
     * @param list<string> $told
     */
    #[Test]
    #[DataProvider('provideRegistrationsOfADeploymentScope')]
    public function aClaimOfADeploymentIsHeldToTheScopeItsClassNames(array $registered, array $told): void
    {
        // Given
        $claims = new ClaimsAskedByName(new ServedClaims([new StandardClaimsProvider(), new InventedClaimsProvider()]));
        $request = ClaimsRequest::fromJson('{"userinfo": {"' . InventedClaimsProvider::CLAIM . '": null}}');

        // When
        $grantable = $claims->grantable(self::clientOf($this->tenant, $registered), $request);

        // Then
        static::assertSame($told, $grantable?->claimNames()->all);
    }

    /**
     * @return iterable<string, array{list<string>, list<string>}>
     */
    public static function provideRegistrationsOfADeploymentScope(): iterable
    {
        yield 'a client that registered the scope' => [['openid', InventedClaimsProvider::SCOPE], [InventedClaimsProvider::CLAIM]];
        yield 'a client that did not' => [['openid', 'profile', 'email'], []];
    }

    /**
     * OIDC Core §3.1.2.4: the person is asked by name for the claims the client may be told and no scope of
     * the request stands for; a claim one of them stands for is agreed to with it, and one the client may
     * not be told is asked of nobody.
     */
    #[Test]
    public function thePersonIsAskedForTheClaimsNoScopeOfTheRequestStandsFor(): void
    {
        // Given
        $request = Requests::authorization(
            $this->client,
            ['openid', 'email'],
            claims: ClaimsRequest::fromJson('{"userinfo": {"email": null, "phone_number": null}, "id_token": {"name": null, "email_verified": null}}'),
        );

        // When
        $asked = $this->claims->toAgreeTo($request);

        // Then
        static::assertSame(['name'], $asked->all);
    }

    #[Test]
    public function aRequestThatAsksForNoClaimByNameAsksThePersonForNone(): void
    {
        // Given
        $request = Requests::authorization($this->client, ['openid', 'profile']);

        // When / Then
        static::assertTrue($this->claims->toAgreeTo($request)->isEmpty());
    }

    /**
     * OIDC Core §5.4, §5.5: a consent answers for a claim asked for by name when it holds it by name or holds
     * the scope that stands for it, and for no other.
     *
     * @param list<string> $scopes what the consent holds
     * @param list<string> $claims what it holds by name
     */
    #[Test]
    #[DataProvider('provideConsents')]
    public function aConsentAnswersForAClaimItHoldsByNameOrThroughItsScope(array $scopes, array $claims, bool $agreed): void
    {
        // Given
        $consent = new Consent(
            Uuid::v7(),
            Fixtures::user($this->tenant),
            $this->client,
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            Fixtures::now(),
            null,
            new ClaimNames($claims),
        );
        $request = Requests::authorization($this->client, claims: ClaimsRequest::fromJson('{"userinfo": {"email": null}}'));

        // When / Then
        static::assertSame($agreed, $this->claims->agreedIn($consent, $request));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, bool}>
     */
    public static function provideConsents(): iterable
    {
        yield 'the claim held by name' => [['openid'], ['email'], true];
        yield 'the scope that stands for it' => [['openid', 'email'], [], true];
        yield 'another scope and another claim' => [['openid', 'profile'], ['name'], false];
        yield 'nothing beyond the scopes of the request' => [['openid'], [], false];
    }

    /**
     * @param list<string> $scopes what it registered
     */
    private static function clientOf(Tenant $tenant, array $scopes): Client
    {
        return Clients::public($tenant, allowedScopes: new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)));
    }
}
