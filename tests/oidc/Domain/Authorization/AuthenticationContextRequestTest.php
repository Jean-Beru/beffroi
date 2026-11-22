<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthenticationContextRequest;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
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
     * OIDC Core §5.5.1.1
     *
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
     * OIDC Core §3.1.2.1
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
     * OIDC Core §5.5.1.1
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
     * OIDC Core §5.5.1.1
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
     * OIDC Core §5.5.1.1
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
     * OIDC Core §5.5.1
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
     * OIDC Core §5.5.1.1
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
     * OIDC Core §5.5.1.1, Decision 0010
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
     * Decision 0010
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
     * OIDC Core §5.5.1.1
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
     * OIDC Core §5.5.1.1
     */
    #[Test]
    public function noClassIsChosenWhenTheSessionSatisfiesNone(): void
    {
        // Given
        $requested = new AuthenticationContextRequest(['phrh', '2']);

        // When / Then
        static::assertNull($requested->firstSatisfiedBy($this->session()));
    }

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
            $this->client->registration->redirectUris[0],
            new Scopes([Scope::openid()]),
            new CodeChallenge(Requests::CHALLENGE, new Sha256CodeChallengeMethod()),
            acrValues: $acrValues,
            claims: $claims === null ? null : ClaimsRequest::fromJson($claims),
        );
    }

    private function session(?string $secondMethod = null): AuthenticationSession
    {
        $session = Fixtures::session();
        if ($secondMethod !== null) {
            $session->recordProof(new AuthenticationMethod($secondMethod), Fixtures::context(Fixtures::now()->modify('+1 minute')));
        }

        return $session;
    }
}
