<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationFactor;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class AuthenticationProofsTest extends TestCase
{
    /**
     * RFC 8176 §2: "amr" is the list of methods, each once, in the order they were first proven.
     */
    #[Test]
    public function itListsEachMethodOnceInTheOrderOfTheirFirstProof(): void
    {
        // Given
        $login = Fixtures::now();

        // When
        $proofs = AuthenticationProofs::of(new AuthenticationMethod(AuthenticationMethod::PIN), $login)->with(AuthenticationMethod::password(), $login)->with(
            AuthenticationMethod::password(),
            $login->modify('+2 hours'),
        );

        // Then
        static::assertSame(['pin', 'pwd'], $proofs->methodReferences());
        static::assertCount(2, $proofs->methods());
        static::assertSame('pin', $proofs->methods()[0]->value);
    }

    /**
     * RFC 8176 §2: "mfa" says several factors were used, next to the methods; the proofs say it when two
     * factors of different kinds were proven, once, even when an authenticator asserted it itself.
     *
     * @param non-empty-list<string> $methods
     * @param non-empty-list<string> $references
     */
    #[Test]
    #[DataProvider('provideMethodsAndTheirReferences')]
    public function mfaIsListedWhenTwoFactorsWereProven(array $methods, array $references): void
    {
        // Given
        $proofs = AuthenticationProofs::ofAll(
            array_map(static fn (string $method): AuthenticationMethod => new AuthenticationMethod($method), $methods),
            Fixtures::now(),
        );

        // When / Then
        static::assertSame($references, $proofs->methodReferences());
    }

    /**
     * @return iterable<string, array{non-empty-list<string>, non-empty-list<string>}>
     */
    public static function provideMethodsAndTheirReferences(): iterable
    {
        yield 'a password alone' => [['pwd'], ['pwd']];
        yield 'a password and a PIN, one kind' => [['pwd', 'pin'], ['pwd', 'pin']];
        yield 'a password and a one-time password' => [['pwd', 'otp'], ['pwd', 'otp', 'mfa']];
        yield 'a password and a hardware key with presence' => [['hwk', 'user', 'pwd'], ['hwk', 'user', 'pwd', 'mfa']];
        yield 'a hardware key verified by a PIN, mfa asserted by the authenticator' => [
            ['hwk', 'user', 'mfa'],
            ['hwk', 'user', 'mfa'],
        ];
        yield 'a password and a verified key, mfa once' => [
            ['pwd', 'hwk', 'user', 'mfa'],
            ['pwd', 'hwk', 'user', 'mfa'],
        ];
    }

    /**
     * OIDC Core §2: the most recent proof is auth_time.
     */
    #[Test]
    public function theMostRecentProofIsTheLatest(): void
    {
        // Given
        $login = Fixtures::now();
        $reauth = $login->modify('+2 hours');
        $proofs = AuthenticationProofs::of(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), $login)->with(
            AuthenticationMethod::password(),
            $reauth,
        );

        // When / Then
        static::assertEquals($reauth, $proofs->latest());
    }

    #[Test]
    public function itDatesTheProofOfEachMethod(): void
    {
        // Given
        $login = Fixtures::now();
        $reauth = $login->modify('+2 hours');
        $proofs = AuthenticationProofs::of(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), $login)->with(
            AuthenticationMethod::password(),
            $reauth,
        );

        // When / Then
        static::assertEquals($login, $proofs->provenAt(new AuthenticationMethod('otp')));
        static::assertSame(
            [
                'otp' => $login->getTimestamp(),
                'pwd' => $reauth->getTimestamp(),
            ],
            $proofs->toTimestamps(),
        );
    }

    /**
     * Two methods of the same kind are one factor; a method of another kind is a second one.
     *
     * @param list<AuthenticationFactor> $factors
     */
    #[Test]
    #[DataProvider('provideProofsAndTheirFactors')]
    public function itCountsTheKindsOfFactorItCovers(AuthenticationProofs $proofs, array $factors): void
    {
        // When / Then
        static::assertSame($factors, $proofs->factors());
    }

    /**
     * @return iterable<string, array{AuthenticationProofs, list<AuthenticationFactor>}>
     */
    public static function provideProofsAndTheirFactors(): iterable
    {
        $now = Fixtures::now();
        yield 'a password' => [AuthenticationProofs::of(AuthenticationMethod::password(), $now), [AuthenticationFactor::Knowledge]];
        yield 'a password and a PIN' => [
            AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('pin'), $now),
            [AuthenticationFactor::Knowledge],
        ];
        yield 'a password and a one-time password, in that order' => [
            AuthenticationProofs::of(AuthenticationMethod::password(), $now)->with(new AuthenticationMethod('otp'), $now),
            [AuthenticationFactor::Knowledge, AuthenticationFactor::Possession],
        ];
        yield 'a hardware key and a fingerprint' => [
            AuthenticationProofs::of(new AuthenticationMethod('hwk'), $now)->with(new AuthenticationMethod('fpt'), $now),
            [AuthenticationFactor::Possession, AuthenticationFactor::Inherence],
        ];
        yield 'a presence check alone' => [AuthenticationProofs::of(new AuthenticationMethod('user'), $now), []];
    }

    /**
     * An assertion of a passkey proves several methods at once, all dated the same.
     */
    #[Test]
    public function severalMethodsProvenAtOnceAreAllDatedTheSame(): void
    {
        // Given
        $now = Fixtures::now();

        // When
        $proofs = AuthenticationProofs::ofAll([new AuthenticationMethod('hwk'), new AuthenticationMethod('user')], $now);

        // Then
        static::assertSame(['hwk', 'user'], $proofs->methodReferences());
        static::assertSame($now, $proofs->provenAt(new AuthenticationMethod('user')));
        static::assertSame($now, $proofs->latest());
    }

    #[Test]
    public function itKnowsTheMethodsItHolds(): void
    {
        // Given
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now());

        // When / Then
        static::assertTrue($proofs->has(AuthenticationMethod::password()));
    }

    #[Test]
    public function itHasNoProofOfAMethodNeverUsed(): void
    {
        // Given
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now());

        // When / Then
        static::assertFalse($proofs->has(new AuthenticationMethod('hwk')));
        static::assertNull($proofs->provenAt(new AuthenticationMethod('hwk')));
    }

    #[Test]
    public function anOlderProofNeverReplacesANewerOne(): void
    {
        // Given
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now());

        // When
        $proofs = $proofs->with(AuthenticationMethod::password(), Fixtures::now()->modify('-1 hour'));

        // Then
        static::assertEquals(Fixtures::now(), $proofs->latest());
    }

    #[Test]
    public function aProofAtTheSameInstantIsNotRecordedTwice(): void
    {
        // Given
        $first = Fixtures::now();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), $first);

        // When
        $proofs = $proofs->with(AuthenticationMethod::password(), Fixtures::now());

        // Then
        static::assertSame($first, $proofs->provenAt(AuthenticationMethod::password()));
    }

    #[Test]
    public function itIsNeverEmpty(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthenticationProofs([]);
    }

    #[Test]
    public function itValidatesTheMethodReferencesItIsBuiltFrom(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthenticationProofs([
            'not valid!' => Fixtures::now(),
        ]);
    }

    /**
     * RFC 8176 §3: the registry is extensible; an upstream provider may send values Symfony and Beffroi do not
     * know, and they are carried as received.
     */
    #[Test]
    #[DataProvider('provideWellFormedMethods')]
    public function anyWellFormedMethodReferenceIsAccepted(string $value): void
    {
        // When / Then
        static::assertSame($value, (string) new AuthenticationMethod($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWellFormedMethods(): iterable
    {
        yield 'registered' => [AuthenticationMethod::HARDWARE_KEY];
        yield 'vendor value' => ['urn:acme:passkey'];
        yield 'dotted' => ['x.custom-1'];
    }

    #[Test]
    #[DataProvider('provideMalformedMethods')]
    public function aMalformedMethodReferenceIsRejected(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthenticationMethod($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedMethods(): iterable
    {
        yield 'empty' => [''];
        yield 'space' => ['pwd otp'];
        yield 'leading dot' => ['.pwd'];
        yield 'too long' => [str_repeat('a', 65)];
    }

    #[Test]
    public function methodsOfTheSameValueAreEqual(): void
    {
        // When / Then
        static::assertTrue(AuthenticationMethod::password()->equals(new AuthenticationMethod('pwd')));
    }

    #[Test]
    public function methodsCompareCaseSensitively(): void
    {
        // When / Then
        static::assertFalse(AuthenticationMethod::password()->equals(new AuthenticationMethod('PWD')));
    }
}
