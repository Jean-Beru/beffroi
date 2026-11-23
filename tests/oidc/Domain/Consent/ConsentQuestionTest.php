<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Consent;

use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Consent\ConsentQuestion;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class ConsentQuestionTest extends TestCase
{
    #[Test]
    public function aQuestionThatAsksNothingAdmitsEveryConsent(): void
    {
        // When / Then
        static::assertTrue(new ConsentQuestion()->admits(self::consent(Fixtures::now())));
    }

    #[Test]
    #[DataProvider('provideGrants')]
    public function theDaysOfTheGrantAdmitWhatWasGrantedOnThem(string $grantedAt, bool $admitted): void
    {
        // Given
        $question = new ConsentQuestion(granted: Period::ofDays(Fixtures::now(), Fixtures::now()));

        // When / Then
        static::assertSame($admitted, $question->admits(self::consent(Fixtures::now()->modify($grantedAt))));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideGrants(): iterable
    {
        yield 'that day' => ['+1 hour', true];
        yield 'the day before' => ['-1 day', false];
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    #[DataProvider('provideScopes')]
    public function theScopeAskedForAdmitsTheConsentsThatGrantIt(string $scope, bool $admitted): void
    {
        // When / Then
        static::assertSame($admitted, new ConsentQuestion(scope: new Scope($scope))->admits(self::consent(Fixtures::now())));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideScopes(): iterable
    {
        yield 'a scope it grants' => ['email', true];
        yield 'a scope it does not grant' => ['phone', false];
    }

    /**
     * OIDC Core §5.5
     */
    #[Test]
    #[DataProvider('provideClaims')]
    public function theClaimAskedForAdmitsTheConsentsThatGrantIt(string $claim, bool $admitted): void
    {
        // When / Then
        static::assertSame($admitted, new ConsentQuestion(claim: $claim)->admits(self::consent(Fixtures::now())));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideClaims(): iterable
    {
        yield 'a claim it grants by name' => ['given_name', true];
        yield 'a claim it does not grant' => ['birthdate', false];
    }

    /**
     * RFC 9396 §2
     */
    #[Test]
    #[DataProvider('provideDetailTypes')]
    public function theTypeOfDetailsAskedForAdmitsTheConsentsThatGrantOne(string $type, bool $admitted): void
    {
        // When / Then
        static::assertSame($admitted, new ConsentQuestion(detailType: $type)->admits(self::consent(Fixtures::now())));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideDetailTypes(): iterable
    {
        yield 'a type it grants' => [AuthorizationDetailTypes::INVENTED, true];
        yield 'a type it does not grant' => ['payment_initiation', false];
    }

    #[Test]
    #[DataProvider('provideApplicationNames')]
    public function theNameTypedAdmitsTheApplicationsWhoseNameHoldsIt(string $typed, bool $admitted): void
    {
        // When / Then
        static::assertSame($admitted, new ConsentQuestion(applicationName: $typed)->admits(self::consent(Fixtures::now())));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideApplicationNames(): iterable
    {
        yield 'a part of the name' => ['page app', true];
        yield 'in another case' => ['SINGLE', true];
        yield 'a name it does not hold' => ['gateway', false];
    }

    private static function consent(DateTimeImmutable $grantedAt): Consent
    {
        $user = Fixtures::user();

        return new Consent(
            Uuid::v7(),
            $user,
            Clients::public($user->tenant),
            new Scopes([Scope::openid(), new Scope('email')]),
            $grantedAt,
            AuthorizationDetailTypes::details(),
            new ClaimNames(['given_name']),
        );
    }
}
