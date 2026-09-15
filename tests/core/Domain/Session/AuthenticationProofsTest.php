<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthenticationProofsTest extends TestCase
{
    /**
     * RFC 8176 §2: "amr" is the list of methods; the most recent proof is auth_time (OIDC Core §2).
     */
    #[Test]
    public function itListsTheMethodsAndDatesTheMostRecentProof(): void
    {
        $login = Fixtures::now();
        $reauth = $login->modify('+2 hours');
        $proofs = AuthenticationProofs::of(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), $login)
            ->with(AuthenticationMethod::password(), $login)
            ->with(AuthenticationMethod::password(), $reauth);

        static::assertSame(['otp', 'pwd'], $proofs->methodReferences());
        static::assertEquals($reauth, $proofs->latest());
        static::assertEquals($login, $proofs->provenAt(new AuthenticationMethod('otp')));
        static::assertTrue($proofs->has(AuthenticationMethod::password()));
        static::assertFalse($proofs->has(new AuthenticationMethod('hwk')));
        static::assertNull($proofs->provenAt(new AuthenticationMethod('hwk')));
        static::assertCount(2, $proofs->methods());
        static::assertSame('otp', $proofs->methods()[0]->value);
        static::assertSame([
            'otp' => $login->getTimestamp(),
            'pwd' => $reauth->getTimestamp(),
        ], $proofs->toTimestamps());
    }

    #[Test]
    public function anOlderProofNeverReplacesANewerOne(): void
    {
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())
            ->with(AuthenticationMethod::password(), Fixtures::now()->modify('-1 hour'));

        static::assertEquals(Fixtures::now(), $proofs->latest());
    }

    #[Test]
    public function aProofAtTheSameInstantIsNotRecordedTwice(): void
    {
        $first = Fixtures::now();
        $sameInstant = Fixtures::now();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), $first)->with(AuthenticationMethod::password(), $sameInstant);

        static::assertSame($first, $proofs->provenAt(AuthenticationMethod::password()));
    }

    #[Test]
    public function itIsNeverEmpty(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AuthenticationProofs([]);
    }

    #[Test]
    public function itValidatesTheMethodReferencesItIsBuiltFrom(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AuthenticationProofs([
            'not valid!' => Fixtures::now(),
        ]);
    }

    /**
     * RFC 8176 §3: the registry is extensible; an upstream provider may send values Symfony and Heidi do not
     * know, and they are carried as received.
     */
    #[Test]
    #[DataProvider('provideWellFormedMethods')]
    public function anyWellFormedMethodReferenceIsAccepted(string $value): void
    {
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
        $this->expectException(InvalidArgumentException::class);

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
    public function methodsCompareByValue(): void
    {
        static::assertTrue(AuthenticationMethod::password()->equals(new AuthenticationMethod('pwd')));
        static::assertFalse(AuthenticationMethod::password()->equals(new AuthenticationMethod('PWD')));
    }
}
