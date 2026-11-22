<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7519 §4.1.3, RFC 8707 §2
 */
final class TokenAudienceTest extends TestCase
{
    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aTokenAskedForNoResourceIsAddressedToItsClient(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant(), resources: Clients::resources());

        // When
        $audience = TokenAudience::of($client, null);

        // Then
        static::assertSame(['spa'], $audience->values);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function aTokenAskedForResourcesIsAddressedToThem(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant(), resources: Clients::resources());

        // When
        $audience = TokenAudience::of($client, ResourceIndicators::of([Clients::CALENDAR]));

        // Then
        static::assertSame([Clients::CALENDAR], $audience->values);
    }

    /**
     * RFC 7519 §4.1.3
     *
     * @param list<string> $values
     * @param string|list<string> $claim
     */
    #[Test]
    #[DataProvider('provideClaims')]
    public function itWritesItselfAsTheClaimItIs(array $values, string|array $claim): void
    {
        // When / Then
        static::assertSame($claim, new TokenAudience($values)->claim());
    }

    /**
     * @return iterable<string, array{list<string>, string|list<string>}>
     */
    public static function provideClaims(): iterable
    {
        yield 'one audience' => [['spa'], 'spa'];
        yield 'several audiences' => [
            [Clients::CALENDAR, Clients::CONTACTS],
            [Clients::CALENDAR, Clients::CONTACTS],
        ];
    }

    /**
     * RFC 7519 §4.1.3
     *
     * @param list<string> $values
     */
    #[Test]
    #[DataProvider('provideReadableClaims')]
    public function itReadsBackAClaimOfEitherShape(mixed $claim, array $values): void
    {
        // When / Then
        static::assertSame($values, TokenAudience::fromClaim($claim)->values);
    }

    /**
     * @return iterable<string, array{mixed, list<string>}>
     */
    public static function provideReadableClaims(): iterable
    {
        yield 'a string' => ['spa', ['spa']];
        yield 'a list' => [
            [Clients::CALENDAR, Clients::CONTACTS],
            [Clients::CALENDAR, Clients::CONTACTS],
        ];
        yield 'a list naming one twice' => [['spa', 'spa'], ['spa']];
    }

    #[Test]
    #[DataProvider('provideClaimsThatAreNotAnAudience')]
    public function itRefusesAClaimThatIsNeitherAStringNorAListOfThem(mixed $claim): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An "aud" claim is a string or a list of strings (RFC 7519 section 4.1.3).');

        // When
        TokenAudience::fromClaim($claim);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideClaimsThatAreNotAnAudience(): iterable
    {
        yield 'nothing' => [null];
        yield 'a number' => [1];
        yield 'an object' => [
            [
                'spa' => 'spa',
            ],
        ];
        yield 'a list holding a number' => [['spa', 1]];
    }

    #[Test]
    public function itRefusesAnEmptyAudience(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An access token is addressed to at least one audience (RFC 7519 section 4.1.3).');

        // When
        new TokenAudience([]);
    }

    #[Test]
    public function itRefusesAnAudienceThatNamesNothing(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An audience names something (RFC 7519 section 4.1.3).');

        // When
        new TokenAudience(['spa', '']);
    }

    #[Test]
    public function itHoldsWhatItWasGiven(): void
    {
        // Given
        $audience = new TokenAudience([Clients::CALENDAR]);

        // When / Then
        static::assertTrue($audience->has(Clients::CALENDAR));
    }

    #[Test]
    public function itDoesNotHoldWhatItWasNotGiven(): void
    {
        // Given
        $audience = new TokenAudience([Clients::CALENDAR]);

        // When / Then
        static::assertFalse($audience->has(Clients::CONTACTS));
    }

    /**
     * @param list<string> $one
     * @param list<string> $other
     */
    #[Test]
    #[DataProvider('provideComparisons')]
    public function itComparesItselfWithAnother(array $one, array $other, bool $equal): void
    {
        // When / Then
        static::assertSame($equal, new TokenAudience($one)->equals(new TokenAudience($other)));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, bool}>
     */
    public static function provideComparisons(): iterable
    {
        yield 'the same one' => [['spa'], ['spa'], true];
        yield 'another one' => [['spa'], [Clients::CALENDAR], false];
        yield 'one more' => [['spa'], ['spa', Clients::CALENDAR], false];
    }

    #[Test]
    public function itCountsWhatItNames(): void
    {
        // When / Then
        static::assertCount(2, new TokenAudience([Clients::CALENDAR, Clients::CONTACTS]));
    }
}
