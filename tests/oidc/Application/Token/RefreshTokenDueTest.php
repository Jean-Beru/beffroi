<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use function array_map;
use Heidi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Token\RefreshTokenDue;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\UserAuthorization;
use Heidi\Oidc\Domain\Token\UserAuthorizationInterface;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeRefreshTokenIssuingGrant;
use Heidi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6749 §4.1.4, OIDC Core §11: whether a response carries a refresh token, asked in one place for every
 * grant that may issue one. What spends one is what the provider is wired with and what the client
 * registered for, and no grant names it.
 */
final class RefreshTokenDueTest extends TestCase
{
    private Tenant $tenant;

    private FakePasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->hasher = new FakePasswordHasher();
    }

    /**
     * A confidential client registered for a grant that spends a refresh token gets one without asking.
     */
    #[Test]
    public function aConfidentialClientRegisteredForTheRenewalGetsOne(): void
    {
        // Given
        $due = new RefreshTokenDue(Grants::served());

        // When / Then
        static::assertTrue($due->forThe($this->authorization($this->confidential())));
    }

    /**
     * A deployment that hands a refresh token only to whoever asked for "offline_access" says so once.
     */
    #[Test]
    public function aDeploymentMayAskForOfflineAccessOfEverybody(): void
    {
        // Given
        $due = new RefreshTokenDue(Grants::served(), false);

        // When / Then
        static::assertFalse($due->forThe($this->authorization($this->confidential())));
        static::assertTrue($due->forThe($this->authorization($this->confidential(), ['openid', 'offline_access'])));
    }

    /**
     * OIDC Core §11: a public client gets one when it asked for "offline_access" and not otherwise.
     *
     * @param list<string> $scopes
     */
    #[Test]
    #[DataProvider('provideScopesOfAPublicClient')]
    public function aPublicClientGetsOneOnlyWhenItAskedForOfflineAccess(array $scopes, bool $expected): void
    {
        // Given
        $due = new RefreshTokenDue(Grants::served());

        // When / Then
        static::assertSame($expected, $due->forThe($this->authorization($this->public(), $scopes)));
    }

    /**
     * @return iterable<string, array{list<string>, bool}>
     */
    public static function provideScopesOfAPublicClient(): iterable
    {
        yield 'without offline_access' => [['openid'], false];
        yield 'with offline_access' => [['openid', 'offline_access'], true];
    }

    /**
     * A refresh token nothing wired could spend is one no response carries, whatever the client asked for.
     */
    #[Test]
    public function aProviderThatSpendsNoneIssuesNone(): void
    {
        // Given
        $due = new RefreshTokenDue(new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]));

        // When / Then
        static::assertFalse($due->forThe($this->authorization($this->confidential(), ['openid', 'offline_access'])));
    }

    /**
     * A client not registered for the grant that spends one gets none, even asking for "offline_access".
     */
    #[Test]
    public function aClientNotRegisteredForTheRenewalGetsNone(): void
    {
        // Given
        $due = new RefreshTokenDue(Grants::served());
        $client = Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET), grantTypes: [Grants::authorizationCode()]);

        // When / Then
        static::assertFalse($due->forThe($this->authorization($client, ['openid', 'offline_access'])));
    }

    private function confidential(): Client
    {
        return Clients::confidential($this->tenant, $this->hasher->hash(Clients::SECRET));
    }

    private function public(): Client
    {
        return Clients::public($this->tenant, grantTypes: [Grants::authorizationCode(), Grants::refreshToken()]);
    }

    /**
     * @param list<string> $scopes
     */
    private function authorization(Client $client, array $scopes = ['openid']): UserAuthorizationInterface
    {
        $session = Fixtures::session(Fixtures::user($this->tenant));
        $asked = new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes));

        return new UserAuthorization(
            Grants::authorizationCode(),
            new SymfonyUuidGenerator()->timeOrdered(),
            $client,
            $session,
            $asked,
            $asked,
            null,
            null,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
        );
    }
}
