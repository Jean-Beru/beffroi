<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationContextPolicy;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthenticationContextRequest;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthenticationContextRequestTest extends TestCase
{
    private Client $client;

    protected function setUp(): void
    {
        $this->client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));
    }

    /**
     * A request that says nothing about "acr" names no class and is not essential.
     */
    #[Test]
    public function aRequestWithoutAcrNamesNoClass(): void
    {
        // When
        $requested = AuthenticationContextRequest::of(Requests::authorization($this->client));

        // Then
        static::assertTrue($requested->namesNoClass());
        static::assertSame([], $requested->values);
        static::assertFalse($requested->essential);
    }

    /**
     * OIDC Core §5.5.1.1: only an essential request that names a class binds the provider, and only such
     * a request is refused when nothing can satisfy it.
     */
    /**
     * @param list<string> $acrValues
     */
    #[Test]
    #[DataProvider('provideAcrRequests')]
    public function aRequestBindsTheProviderWhenItIsEssentialAndNamesAClass(?string $claims, array $acrValues, bool $demands): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(claims: $claims, acrValues: $acrValues));

        // Then
        static::assertSame($demands, $requested->demandsAClass());
    }

    /**
     * @return iterable<string, array{string|null, list<string>, bool}>
     */
    public static function provideAcrRequests(): iterable
    {
        yield 'nothing requested' => [null, [], false];
        yield 'acr_values, voluntary by definition' => [null, ['phr'], false];
        yield 'essential and naming a class' => ['{"id_token": {"acr": {"essential": true, "values": ["phr"]}}}', [], true];
        yield 'essential and naming none' => ['{"id_token": {"acr": {"essential": true}}}', [], false];
        yield 'voluntary claim request naming a class' => ['{"id_token": {"acr": {"values": ["phr"]}}}', [], false];
    }

    /**
     * OIDC Core §3.1.2.1 "acr_values": a voluntary request, in the client's order of preference.
     */
    #[Test]
    public function acrValuesIsAVoluntaryRequest(): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(acrValues: ['phr', '2']));

        // Then
        static::assertSame(['phr', '2'], $requested->values);
        static::assertFalse($requested->essential);
    }

    /**
     * OIDC Core §5.5.1.1: an individual claim request with "values" and "essential": true.
     */
    #[Test]
    public function anEssentialClaimRequestWithValuesIsEssential(): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(claims: '{"id_token": {"acr": {"essential": true, "values": ["2", "1"]}}}'));

        // Then
        static::assertSame(['2', '1'], $requested->values);
        static::assertTrue($requested->essential);
    }

    /**
     * OIDC Core §5.5.1.1: "value" is the one-element form of "values".
     */
    #[Test]
    public function aClaimRequestWithASingleValueNamesThatClass(): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(claims: '{"id_token": {"acr": {"essential": true, "value": "1"}}}'));

        // Then
        static::assertSame(['1'], $requested->values);
        static::assertTrue($requested->essential);
    }

    /**
     * OIDC Core §5.5.1.1: an individual claim request without "essential" is voluntary.
     */
    #[Test]
    public function aClaimRequestWithoutEssentialIsVoluntary(): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(claims: '{"id_token": {"acr": {"values": ["2"]}}}'));

        // Then
        static::assertSame(['2'], $requested->values);
        static::assertFalse($requested->essential);
    }

    /**
     * OIDC Core §5.5.1: a claim requested with null, or essential without a value, names no class: the
     * claim is wanted, whatever its value.
     */
    #[Test]
    #[DataProvider('provideClaimRequestsNamingNoClass')]
    public function aClaimRequestWithoutAValueNamesNoClass(string $claims): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(claims: $claims));

        // Then
        static::assertTrue($requested->namesNoClass());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideClaimRequestsNamingNoClass(): iterable
    {
        yield 'null' => ['{"id_token": {"acr": null}}'];
        yield 'essential without a value' => ['{"id_token": {"acr": {"essential": true}}}'];
        yield 'an empty object' => ['{"id_token": {"acr": {}}}'];
    }

    /**
     * OIDC Core §5.5.1.1 leaves both forms at once unspecified: the individual claim request, the more
     * specific, wins over "acr_values".
     */
    #[Test]
    public function theIndividualClaimRequestWinsOverAcrValues(): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(
            acrValues: ['phrh'],
            claims: '{"id_token": {"acr": {"essential": true, "values": ["1"]}}}',
        ));

        // Then
        static::assertSame(['1'], $requested->values);
        static::assertTrue($requested->essential);
    }

    /**
     * An individual claim request for another claim than "acr" leaves "acr_values" in force.
     */
    #[Test]
    public function aClaimRequestForAnotherClaimLeavesAcrValuesInForce(): void
    {
        // When
        $requested = AuthenticationContextRequest::of($this->request(acrValues: ['1'], claims: '{"id_token": {"auth_time": {"essential": true}}}'));

        // Then
        static::assertSame(['1'], $requested->values);
        static::assertFalse($requested->essential);
    }

    /**
     * OIDC Core §5.5.1.1, decision 0010: the requested classes among those the provider can prove, in
     * the client's order; what a step-up may ask for, nothing when the request cannot be met.
     *
     * @param list<string|int|float|bool> $values
     * @param list<string> $among
     */
    #[Test]
    #[DataProvider('provideRequestsAndTheirClassesAmongTheProvableOnes')]
    public function theRequestedClassesAmongTheProvableOnesKeepTheClientsOrder(array $values, array $among): void
    {
        // Given
        $requested = new AuthenticationContextRequest($values, true);

        // When
        $classes = $requested->among([AuthenticationContextClass::singleFactor(), AuthenticationContextClass::twoFactors()]);

        // Then
        static::assertSame($among, array_map(static fn (AuthenticationContextClass $class): string => $class->value, $classes));
    }

    /**
     * @return iterable<string, array{list<string|int|float|bool>, list<string>}>
     */
    public static function provideRequestsAndTheirClassesAmongTheProvableOnes(): iterable
    {
        yield 'a provable class' => [['1'], ['1']];
        yield 'a provable class after one that is not' => [['phrh', '2'], ['2']];
        yield 'two provable classes, the client\'s order' => [['2', '1'], ['2', '1']];
        yield 'a class that is not provable' => [['phrh'], []];
        yield 'a number that looks like a level' => [[1], []];
        yield 'a boolean' => [[true], []];
        yield 'nothing' => [[], []];
    }

    /**
     * Decision 0010: the requested values that name a class of the policy of the tenant, in the client's
     * order; a name the tenant did not declare names none.
     */
    #[Test]
    public function theClassesOfAPolicyAreTheRequestedNamesItDeclares(): void
    {
        // Given
        $requested = new AuthenticationContextRequest(['urn:mace:incommon:iap:silver', '2', 1, 'phr']);

        // When
        $classes = $requested->classesOf(AuthenticationContextPolicy::default());

        // Then
        static::assertSame(['2', 'phr'], array_map(static fn (AuthenticationContextClass $class): string => $class->value, $classes));
    }

    /**
     * OIDC Core §5.5.1.1: the first requested class the session satisfies, in the client's order.
     */
    #[Test]
    public function theFirstRequestedClassTheSessionSatisfiesIsChosen(): void
    {
        // Given
        $requested = new AuthenticationContextRequest(['phrh', '2', '1']);

        // When
        $class = $requested->firstSatisfiedBy($this->session(AuthenticationMethod::ONE_TIME_PASSWORD));

        // Then
        static::assertSame('2', $class?->value);
    }

    /**
     * OIDC Core §5.5.1.1: a session that satisfies no requested class chooses none; the caller answers
     * with the current class when the request is voluntary.
     */
    #[Test]
    public function noClassIsChosenWhenTheSessionSatisfiesNone(): void
    {
        // Given
        $requested = new AuthenticationContextRequest(['phrh', '2']);

        // When / Then
        static::assertNull($requested->firstSatisfiedBy($this->session()));
    }

    /**
     * A value that names no class, a number, a boolean or malformed text, matches nothing and is passed
     * over for the next one.
     */
    #[Test]
    public function aValueThatNamesNoClassIsPassedOver(): void
    {
        // Given
        $requested = new AuthenticationContextRequest([1, true, 'level 1', '1']);

        // When
        $class = $requested->firstSatisfiedBy($this->session());

        // Then
        static::assertSame('1', $class?->value);
    }

    /**
     * @param list<string> $acrValues
     */
    private function request(array $acrValues = [], ?string $claims = null): AuthorizationRequest
    {
        return new AuthorizationRequest(
            $this->client,
            $this->client->redirectUris[0],
            new Scopes([Scope::openid()]),
            new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256),
            acrValues: $acrValues,
            claims: $claims === null ? null : ClaimsRequest::fromJson($claims),
        );
    }

    /**
     * Alice, authenticated with a password, and with a second method when one is given.
     */
    private function session(?string $secondMethod = null): AuthenticationSession
    {
        $session = Fixtures::session();
        if ($secondMethod !== null) {
            $session->recordProof(new AuthenticationMethod($secondMethod), Fixtures::context(Fixtures::now()->modify('+1 minute')));
        }

        return $session;
    }
}
