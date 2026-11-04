<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AccessTokenTest extends TestCase
{
    #[Test]
    public function itCarriesItsValueAndItsDates(): void
    {
        // When
        $token = new AccessToken('at.value', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // Then
        static::assertSame('at.value', $token->value);
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
    }

    /**
     * RFC 6749 §5.1
     */
    #[Test]
    #[DataProvider('provideLifetimes')]
    public function itKnowsItsLifetimeInSeconds(string $lifetime, int $expiresIn): void
    {
        // Given
        $token = new AccessToken('at.value', Fixtures::now(), Fixtures::now()->modify($lifetime));

        // When / Then
        static::assertSame($expiresIn, $token->expiresIn());
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideLifetimes(): iterable
    {
        yield 'ten minutes' => ['+10 minutes', 600];
        yield 'one second' => ['+1 second', 1];
    }

    #[Test]
    public function itRefusesAnEmptyValue(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AccessToken('', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    #[Test]
    #[DataProvider('provideExpiriesWithinTheFirstSecond')]
    public function itRefusesToExpireWithinTheSecondItWasIssued(DateTimeImmutable $expiresAt): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('one second');

        // When
        new AccessToken('at.value', Fixtures::now(), $expiresAt);
    }

    /**
     * @return iterable<string, array{DateTimeImmutable}>
     */
    public static function provideExpiriesWithinTheFirstSecond(): iterable
    {
        yield 'at issuance' => [Fixtures::now()];
        yield 'half a second later' => [Fixtures::now()->modify('+500 milliseconds')];
        yield 'before issuance' => [Fixtures::now()->modify('-1 second')];
    }
}
