<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Token;

use Heidi\Oidc\Application\Token\GrantNames;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\FakeGrant;
use Heidi\Oidc\Tests\Fixture\FakeRefreshTokenIssuingGrant;
use Heidi\Oidc\Tests\Fixture\FakeRefreshTokenSpendingGrant;
use Heidi\Oidc\Tests\Fixture\Grants;
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
