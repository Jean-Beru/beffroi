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

/**
 * The grants the token endpoint serves are named by the grants themselves, so that what the endpoint
 * serves, what a client may register and what the document announces cannot disagree (issue #98).
 */
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
     * RFC 6749 §4.4, §3.1.2: which of the wired grants a client uses for itself, and which send the user's
     * browser back to it, is what they declare; it is what decides which lists a registration of them must
     * carry and must not.
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
     * RFC 8628 §3.3: which of the wired grants asks its user somewhere other than in the client's own
     * browser is what they declare, and is what the endpoint where such a flow starts reads.
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
     * CIBA Core §7: which of the wired grants has this provider reach its user is what they declare, and
     * is what tells the two endpoints of the two waiting flows apart.
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
     * RFC 8693 §2.1: which of the wired grants takes a token and gives a token back is what they declare, and
     * is what decides which registrations must carry what a client may present.
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
     * RFC 6749 §2.1: which of the wired grants is served only to a client that authenticates itself is
     * what they declare, a grant a client uses for itself and one that exchanges a token among them, and is
     * what decides which registrations a public client is refused and which requests of one the token
     * endpoint refuses.
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

    /**
     * Every wired grant that declares a capability is listed, in the order they are wired: the list is what
     * they all declare and not what the first of them does.
     */
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

    /**
     * A wiring where no grant declares either is a wiring where no client registers a redirect URI and
     * none acts for itself: the lists are read from the grants and never guessed from their names.
     */
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
     * RFC 6749 §4.5: an extension grant names itself by an absolute URI, and the provider serves it
     * because it is wired and for no other reason.
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
     * RFC 6749 §4.1.4: which of the wired grants may answer with a refresh token, and which spend one
     * (§6), is what they declare and never a rule written about their names.
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
