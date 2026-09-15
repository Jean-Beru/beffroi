<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\KeyManagement;

use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

final class EnvelopeKeySealerTest extends TestCase
{
    /**
     * Architecture §3.3: the private key is stored sealed, exists in clear in memory only, and the KMS never
     * sees it (envelope mode wraps a data key).
     */
    #[Test]
    public function itSealsAPrivateJwkIntoOpaqueBytes(): void
    {
        // Given
        $private = Keys::pair()->privateJwk;

        // When
        $sealed = Keys::sealer()->seal($private);

        // Then
        static::assertStringNotContainsString($private['d'], $sealed);
        static::assertStringNotContainsString($private['n'], $sealed);
    }

    #[Test]
    public function itOpensWhatItSealed(): void
    {
        // Given
        $private = Keys::pair()->privateJwk;
        $sealed = Keys::sealer()->seal($private);

        // When
        $opened = Keys::sealer()->unseal($sealed);

        // Then
        static::assertSame($private, $opened);
    }

    #[Test]
    public function twoSealsOfTheSameKeyDiffer(): void
    {
        // When / Then
        static::assertNotSame(Keys::sealer()->seal(Keys::pair()->privateJwk), Keys::sealer()->seal(Keys::pair()->privateJwk));
    }

    #[Test]
    public function itRefusesTamperedBytes(): void
    {
        // Given
        $tampered = Keys::sealer()->seal(Keys::pair()->privateJwk);
        $tampered[strlen($tampered) - 1] = $tampered[strlen($tampered) - 1] === 'a' ? 'b' : 'a';

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Keys::sealer()->unseal($tampered);
    }

    #[Test]
    public function itRefusesGarbage(): void
    {
        // Then
        $this->expectException(RuntimeException::class);

        // When
        Keys::sealer()->unseal('not an envelope');
    }
}
