<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Oidc\Application\Token\GrantNames;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\FakeClientActingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeClientAuthenticatingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeExchangingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeGrant;
use Beffroi\Oidc\Tests\Fixture\FakeRefreshTokenIssuingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeRefreshTokenSpendingGrant;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ServedGrantsTest extends TestCase
{
    #[Test]
    public function theyAreTheGrantsTheTokenEndpointIsWiredWith(): void
    {
        // Given
        $served = Grants::served();

        // When
        $grantTypes = $served->servedGrantTypes();

        // Then
        static::assertSame(['authorization_code', 'refresh_token'], GrantNames::of($grantTypes));
    }

    /**
     * RFC 6749 §4.4, §3.1.2
     */
    #[Test]
    public function whatEachGrantDoesWithAUserIsWhatItDeclares(): void
    {
        // Given
        $served = Grants::servedWithClientCredentials();

        // When
        $forTheClient = $served->actingForTheClientItself();
        $toTheUser = $served->sendingTheUserToTheClient();

        // Then
        static::assertSame(['client_credentials'], GrantNames::of($forTheClient));
        static::assertSame(['authorization_code'], GrantNames::of($toTheUser));
    }

    /**
     * RFC 8628 §3.3
     */
    #[Test]
    public function whichGrantsAskTheirUserOnAnotherDeviceIsWhatTheyDeclare(): void
    {
        // Given
        $served = Grants::servedWithDeviceCode();

        // When
        $elsewhere = $served->askingTheUserOnAnotherDevice();

        // Then
        static::assertSame(['urn:ietf:params:oauth:grant-type:device_code'], GrantNames::of($elsewhere));
        static::assertSame(['authorization_code'], GrantNames::of($served->sendingTheUserToTheClient()));
    }

    /**
     * CIBA Core §7
     */
    #[Test]
    public function whichGrantsHaveTheProviderReachTheirUserIsWhatTheyDeclare(): void
    {
        // Given
        $served = Grants::servedWithCiba();

        // When
        $backchannel = $served->askingTheUserThroughABackchannel();

        // Then
        static::assertSame(['urn:openid:params:grant-type:ciba'], GrantNames::of($backchannel));
        static::assertSame([], GrantNames::of($served->askingTheUserOnAnotherDevice()));
        static::assertSame([], GrantNames::of(Grants::servedWithDeviceCode()->askingTheUserThroughABackchannel()));
    }

    /**
     * RFC 8693 §2.1
     */
    #[Test]
    public function whichGrantsExchangeATokenIsWhatTheyDeclare(): void
    {
        // Given
        $served = Grants::servedWithTokenExchange();

        // When
        $exchanging = $served->exchangingTokens();

        // Then
        static::assertSame(['urn:ietf:params:oauth:grant-type:token-exchange'], GrantNames::of($exchanging));
        static::assertSame([], GrantNames::of(Grants::servedWithClientCredentials()->exchangingTokens()));
    }

    /**
     * RFC 6749 §2.1
     */
    #[Test]
    public function whichGrantsRequireClientAuthenticationIsWhatTheyDeclare(): void
    {
        // Given
        $served = new ServedGrants([
            new FakeRefreshTokenIssuingGrant(Grants::authorizationCode()),
            new FakeClientActingGrant(Grants::clientCredentials()),
            new FakeExchangingGrant(Grants::tokenExchange()),
            new FakeClientAuthenticatingGrant(Grants::jwtBearer()),
        ]);

        // When
        $authenticating = $served->requiringClientAuthentication();

        // Then
        static::assertSame(
            [
                'client_credentials',
                'urn:ietf:params:oauth:grant-type:token-exchange',
                'urn:ietf:params:oauth:grant-type:jwt-bearer',
            ],
            GrantNames::of($authenticating),
        );
    }

    #[Test]
    public function everyGrantThatDeclaresACapabilityIsListed(): void
    {
        // Given
        $served = new ServedGrants([
            new FakeClientActingGrant(Grants::clientCredentials()),
            new FakeClientActingGrant(Grants::invented()),
        ]);

        // When
        $forTheClient = $served->actingForTheClientItself();

        // Then
        static::assertSame(['client_credentials', 'urn:example:params:oauth:grant-type:invented'], GrantNames::of($forTheClient));
    }

    #[Test]
    public function aWiringOfGrantsThatDeclareNeitherHasNeither(): void
    {
        // Given
        $served = new ServedGrants([new FakeGrant(Grants::invented())]);

        // When / Then
        static::assertSame([], $served->actingForTheClientItself());
        static::assertSame([], $served->sendingTheUserToTheClient());
        static::assertSame([], $served->askingTheUserOnAnotherDevice());
        static::assertSame([], $served->requiringClientAuthentication());
    }

    /**
     * RFC 6749 §4.5
     */
    #[Test]
    public function aGrantNamedByAnythingItLikesIsServedUnderThatName(): void
    {
        // Given
        $served = new ServedGrants([new FakeGrant(Grants::invented())]);

        // When
        $grant = $served->named('urn:example:params:oauth:grant-type:invented') ?? static::fail('The wired grant is served under its own name.');

        // Then
        static::assertTrue($grant->grantType()->equals(Grants::invented()));
    }

    #[Test]
    public function aNameNoWiredGrantGivesItselfIsServedByNone(): void
    {
        // Given
        $served = Grants::served();

        // When
        $grant = $served->named('password');

        // Then
        static::assertNull($grant);
    }

    /**
     * RFC 6749 §4.1.4, §6
     */
    #[Test]
    public function whatEachGrantMakesOfARefreshTokenIsWhatItDeclares(): void
    {
        // Given
        $served = Grants::served();

        // When
        $issuing = $served->issuingRefreshTokens();
        $spending = $served->spendingRefreshTokens();

        // Then
        static::assertSame(['authorization_code'], GrantNames::of($issuing));
        static::assertSame(['refresh_token'], GrantNames::of($spending));
    }

    #[Test]
    public function aGrantThatDeclaresNothingOfRefreshTokensIsNeitherOfThem(): void
    {
        // Given
        $served = new ServedGrants([new FakeGrant(Grants::invented())]);

        // When
        $grantTypes = [...$served->issuingRefreshTokens(), ...$served->spendingRefreshTokens()];

        // Then
        static::assertSame([], $grantTypes);
    }

    #[Test]
    public function aTokenEndpointWithoutAGrantIsRefused(): void
    {
        // Given
        $served = new ServedGrants([]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The token endpoint serves at least one grant.');

        // When
        $served->servedGrantTypes();
    }

    #[Test]
    public function aGrantWiredTwiceIsRefused(): void
    {
        // Given
        $served = new ServedGrants([
            new FakeRefreshTokenIssuingGrant(Grants::authorizationCode()),
            new FakeRefreshTokenSpendingGrant(Grants::authorizationCode()),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The grant "authorization_code" is wired twice.');

        // When
        $served->servedGrantTypes();
    }
}
