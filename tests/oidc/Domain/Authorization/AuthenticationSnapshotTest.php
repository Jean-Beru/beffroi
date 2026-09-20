<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class AuthenticationSnapshotTest extends TestCase
{
    private DateTimeImmutable $authenticatedAt;

    protected function setUp(): void
    {
        $this->authenticatedAt = new DateTimeImmutable('2026-09-20T12:00:00+00:00');
    }

    #[Test]
    public function itFreezesWhenHowAndAtWhichClassTheUserAuthenticated(): void
    {
        // When
        $snapshot = new AuthenticationSnapshot($this->authenticatedAt, ['pwd', 'otp'], '2');

        // Then
        static::assertSame($this->authenticatedAt, $snapshot->authenticatedAt);
        static::assertSame(['pwd', 'otp'], $snapshot->methods);
        static::assertSame('2', $snapshot->contextClass);
    }

    /**
     * RFC 8176: at least one method.
     */
    #[Test]
    public function itRefusesAnEmptyMethodList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An authentication records at least one method (RFC 8176).');

        // When
        new AuthenticationSnapshot($this->authenticatedAt, [], '1');
    }

    /**
     * RFC 8176 §2: a method reference is a well-formed token.
     */
    #[Test]
    public function itRefusesAMethodThatIsNotWellFormed(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not a well-formed authentication method reference');

        // When
        new AuthenticationSnapshot($this->authenticatedAt, ['pwd', 'not a method'], '1');
    }

    /**
     * OIDC Core §2: "acr" is printable ASCII without space.
     */
    #[Test]
    public function itRefusesAClassThatIsNotWellFormed(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An authentication records a well-formed authentication context class reference (OIDC Core section 2).');

        // When
        new AuthenticationSnapshot($this->authenticatedAt, ['pwd'], 'level one');
    }

    #[Test]
    public function itIsTakenFromASessionWithTheClassAnswered(): void
    {
        // Given
        $user = Fixtures::user();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), $this->authenticatedAt->modify('-1 hour'))
            ->with(new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY), $this->authenticatedAt);
        $session = new AuthenticationSession(Uuid::v7(), $user->tenant, $user, $this->authenticatedAt, $proofs, Fixtures::context($this->authenticatedAt), $this->authenticatedAt->modify('+12 hours'));

        // When
        $snapshot = AuthenticationSnapshot::ofSession($session, AuthenticationContextClass::phishingResistant());

        // Then
        static::assertEquals($this->authenticatedAt, $snapshot->authenticatedAt);
        static::assertSame(['pwd', 'hwk'], $snapshot->methods);
        static::assertSame('phr', $snapshot->contextClass);
    }

    #[Test]
    public function itIsWrittenAsTheThreeClaimsOfOidcCore(): void
    {
        // Given
        $snapshot = new AuthenticationSnapshot($this->authenticatedAt, ['pwd'], '1');

        // When
        $claims = $snapshot->toClaims();

        // Then
        static::assertSame([
            'auth_time' => 1789905600,
            'acr' => '1',
            'amr' => ['pwd'],
        ], $claims);
    }

    #[Test]
    public function itIsReadBackFromTheClaimsItWrote(): void
    {
        // Given
        $written = new AuthenticationSnapshot($this->authenticatedAt, ['pwd', 'otp'], '2');

        // When
        $read = AuthenticationSnapshot::fromClaims([
            'iss' => 'https://id.acme.example',
            ...$written->toClaims(),
        ]);

        // Then
        static::assertEquals($written, $read);
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[Test]
    #[DataProvider('provideClaimsNotWrittenHere')]
    public function itRefusesClaimsThisProviderDidNotWrite(array $claims, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($message);

        // When
        AuthenticationSnapshot::fromClaims($claims);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideClaimsNotWrittenHere(): iterable
    {
        $written = [
            'auth_time' => 1789473600,
            'acr' => '1',
            'amr' => ['pwd'],
        ];
        yield 'no auth_time' => [self::without($written, 'auth_time'), 'The auth_time claim is not a number of seconds.'];
        yield 'auth_time as a string' => [[
            ...$written,
            'auth_time' => '1789473600',
        ], 'The auth_time claim is not a number of seconds.'];
        yield 'no amr' => [self::without($written, 'amr'), 'The amr claim is not a list.'];
        yield 'amr as a string' => [[
            ...$written,
            'amr' => 'pwd',
        ], 'The amr claim is not a list.'];
        yield 'amr as a map' => [[
            ...$written,
            'amr' => [
                'first' => 'pwd',
            ],
        ], 'The amr claim is not a list.'];
        yield 'amr with an empty value' => [[
            ...$written,
            'amr' => [''],
        ], 'The amr claim is not a list of strings.'];
        yield 'amr with a number' => [[
            ...$written,
            'amr' => [1],
        ], 'The amr claim is not a list of strings.'];
        yield 'amr empty' => [[
            ...$written,
            'amr' => [],
        ], 'An authentication records at least one method (RFC 8176).'];
        yield 'no acr' => [self::without($written, 'acr'), 'The acr claim is not a string.'];
        yield 'acr empty' => [[
            ...$written,
            'acr' => '',
        ], 'The acr claim is not a string.'];
        yield 'acr as a number' => [[
            ...$written,
            'acr' => 1,
        ], 'The acr claim is not a string.'];
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    private static function without(array $claims, string $name): array
    {
        unset($claims[$name]);

        return $claims;
    }
}
