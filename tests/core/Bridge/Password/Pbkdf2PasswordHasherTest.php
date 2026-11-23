<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Password;

use function base64_encode;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Bridge\Password\Algorithm\Bcrypt;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha256;
use Beffroi\Core\Bridge\Password\Algorithm\Pbkdf2Sha512;
use Beffroi\Core\Bridge\Password\Pbkdf2PasswordHasher;
use Beffroi\Core\Domain\Credential\PasswordAlgorithmInterface;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use function hex2bin;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function substr;

/**
 * RFC 8018 §5.2
 */
final class Pbkdf2PasswordHasherTest extends TestCase
{
    /**
     * PBKDF2-HMAC-SHA-256 of "passwd" under the salt "salt", one iteration, 64 octets.
     */
    private const string SHA256_KEY = '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783';

    /**
     * PBKDF2-HMAC-SHA-512 of the same.
     */
    private const string SHA512_KEY = 'c74319d99499fc3e9013acff597c23c5baf0a0bec5634c46b8352b793e324723d55caa76b2b25c43402dcfdc06cdcf66f95b7d0429420b39520006749c51a04e';

    private Pbkdf2PasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new Pbkdf2PasswordHasher(new FakePasswordHasher());
    }

    /**
     * RFC 7914 §11
     */
    #[Test]
    #[DataProvider('provideHashesOfPasswd')]
    public function itVerifiesThePasswordAHashWasDerivedFrom(PasswordHash $hash): void
    {
        // When / Then
        static::assertTrue($this->hasher->verify($hash, 'passwd'));
    }

    /**
     * @return iterable<string, array{PasswordHash}>
     */
    public static function provideHashesOfPasswd(): iterable
    {
        yield 'pbkdf2-sha256' => [self::hashOfPasswd(new Pbkdf2Sha256(), self::SHA256_KEY)];

        yield 'pbkdf2-sha512' => [self::hashOfPasswd(new Pbkdf2Sha512(), self::SHA512_KEY)];
    }

    #[Test]
    #[DataProvider('provideHashesOfPasswd')]
    public function itRefusesAnotherPassword(PasswordHash $hash): void
    {
        // When / Then
        static::assertFalse($this->hasher->verify($hash, 'passwe'));
    }

    #[Test]
    public function theKeyIsDerivedToTheLengthOfTheStoredOne(): void
    {
        // Given
        $hash = self::hashOfPasswd(new Pbkdf2Sha256(), substr(self::SHA256_KEY, 0, 64));

        // When / Then
        static::assertTrue($this->hasher->verify($hash, 'passwd'));
    }

    /**
     * @param array<string, int|string> $parameters
     */
    #[Test]
    #[DataProvider('provideHashesThatCannotBeRead')]
    public function aHashThatCannotBeReadVerifiesNoPassword(string $key, array $parameters): void
    {
        // Given
        $hash = new PasswordHash(new Pbkdf2Sha256(), $key, $parameters);

        // When / Then
        static::assertFalse($this->hasher->verify($hash, 'passwd'));
    }

    /**
     * @return iterable<string, array{string, array<string, int|string>}>
     */
    public static function provideHashesThatCannotBeRead(): iterable
    {
        $key = base64_encode(self::octets(self::SHA256_KEY));

        yield 'a key that is not base64' => ['not base64!', ['salt' => 'c2FsdA==', 'iterations' => 1]];

        yield 'no salt' => [$key, ['iterations' => 1]];

        yield 'a salt that is not base64' => [$key, ['salt' => 'not base64!', 'iterations' => 1]];

        yield 'no iterations' => [$key, ['salt' => 'c2FsdA==']];

        yield 'iterations written as text' => [$key, ['salt' => 'c2FsdA==', 'iterations' => '1']];

        yield 'no iteration at all' => [$key, ['salt' => 'c2FsdA==', 'iterations' => 0]];
    }

    #[Test]
    public function everyHashIsReplaced(): void
    {
        // When / Then
        static::assertTrue($this->hasher->needsRehash(self::hashOfPasswd(new Pbkdf2Sha256(), self::SHA256_KEY)));
    }

    #[Test]
    public function aNewHashIsTheOneOfTheHasherOfToday(): void
    {
        // When
        $hash = $this->hasher->hash('passwd');

        // Then
        static::assertSame(Argon2id::NAME, $hash->algorithm->name());
    }

    #[Test]
    #[DataProvider('provideAlgorithms')]
    public function itSupportsThePbkdf2AlgorithmsOnly(PasswordAlgorithmInterface $algorithm, bool $supported): void
    {
        // When / Then
        static::assertSame($supported, $this->hasher->supports($algorithm));
    }

    /**
     * @return iterable<string, array{PasswordAlgorithmInterface, bool}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield 'pbkdf2-sha256' => [new Pbkdf2Sha256(), true];

        yield 'pbkdf2-sha512' => [new Pbkdf2Sha512(), true];

        yield 'argon2id' => [new Argon2id(), false];

        yield 'bcrypt' => [new Bcrypt(), false];
    }

    #[Test]
    public function itRefusesToVerifyAHashOfAnotherAlgorithm(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The PBKDF2 hasher does not handle "bcrypt" hashes; route them through the registry.');

        // When
        $this->hasher->verify(new PasswordHash(new Bcrypt(), '$2y$04$digest'), 'passwd');
    }

    /**
     * As Keycloak stores one: the derived key and the salt in base64, the iterations beside them.
     */
    private static function hashOfPasswd(PasswordAlgorithmInterface $algorithm, string $hexadecimalKey): PasswordHash
    {
        return new PasswordHash($algorithm, base64_encode(self::octets($hexadecimalKey)), [
            'salt' => base64_encode('salt'),
            'iterations' => 1,
        ]);
    }

    private static function octets(string $hexadecimal): string
    {
        $octets = hex2bin($hexadecimal);

        return $octets !== false ? $octets : static::fail('The fixture is hexadecimal.');
    }
}
