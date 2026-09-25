<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Secret;

use Heidi\Oidc\Tests\Fixture\Secrets;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

final class DrawnSecretTest extends TestCase
{
    /**
     * Architecture §4.6: stored as its SHA-256.
     */
    #[Test]
    public function aValueIsHashedWithSha256(): void
    {
        // When / Then
        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', DrawnSecret::digestOf(''));
        static::assertSame(64, strlen(DrawnSecret::digestOf(Secrets::draw())));
    }

    #[Test]
    public function twoValuesHashDifferently(): void
    {
        // Given
        $value = Secrets::draw();
        $again = Secrets::draw();

        // When / Then
        static::assertSame(DrawnSecret::digestOf($value), DrawnSecret::digestOf($value));
        static::assertNotSame(DrawnSecret::digestOf($value), DrawnSecret::digestOf($again));
    }

    /**
     * Every record that holds one checks the shape of what it was handed rather than trusting it: the
     * digest of a value is not the value, and neither is anything else.
     */
    #[Test]
    #[DataProvider('provideDigests')]
    public function itTellsADigestFromAnythingElse(string $candidate, bool $isDigest): void
    {
        // When / Then
        static::assertSame($isDigest, DrawnSecret::isDigest($candidate));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideDigests(): iterable
    {
        yield 'the digest of a value' => [DrawnSecret::digestOf(Secrets::draw()), true];
        yield 'a value, which is not its own digest' => [Secrets::draw(), false];
        yield 'nothing' => ['', false];
        yield 'uppercase hexadecimal' => ['E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855', false];
        yield 'one character short' => ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85', false];
        yield 'a digest with something after it' => ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n", false];
    }

    #[Test]
    #[DataProvider('provideValues')]
    public function itTellsAValueItDrewFromAnythingElse(string $candidate, bool $isValue): void
    {
        // When / Then
        static::assertSame($isValue, DrawnSecret::isValue($candidate));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideValues(): iterable
    {
        yield 'a value it drew' => [Secrets::draw(), true];
        yield 'nothing' => ['', false];
        yield 'a digest, which is longer' => [DrawnSecret::digestOf('x'), false];
        yield 'base64 with padding' => ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==', false];
        yield 'a value with something after it' => [Secrets::draw() . "\n", false];
    }
}
