<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use function array_map;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\RefreshTokenDue;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\UserAuthorization;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeRefreshTokenIssuingGrant;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 6749 §4.1.4, OIDC Core §11
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

    #[Test]
    public function aConfidentialClientRegisteredForTheRenewalGetsOne(): void
    {
        // Given
        $due = new RefreshTokenDue(Grants::served());

        // When / Then
        static::assertTrue($due->forThe($this->authorization($this->confidential())));
    }

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
     * OIDC Core §11
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

    #[Test]
    public function aProviderThatSpendsNoneIssuesNone(): void
    {
        // Given
        $due = new RefreshTokenDue(new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]));

        // When / Then
        static::assertFalse($due->forThe($this->authorization($this->confidential(), ['openid', 'offline_access'])));
    }

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
