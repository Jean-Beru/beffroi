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
    public function itSealsAPrivateJwkIntoOpaqueBytesAndOpensItBack(): void
    {
        $private = Keys::pair()->privateJwk;

        $sealed = Keys::sealer()->seal($private);

        static::assertStringNotContainsString($private['d'], $sealed);
        static::assertStringNotContainsString($private['n'], $sealed);
        static::assertSame($private, Keys::sealer()->unseal($sealed));
    }

    #[Test]
    public function twoSealsOfTheSameKeyDiffer(): void
    {
        static::assertNotSame(Keys::sealer()->seal(Keys::pair()->privateJwk), Keys::sealer()->seal(Keys::pair()->privateJwk));
    }

    #[Test]
    public function itRefusesTamperedOrForeignBytes(): void
    {
        $sealed = Keys::sealer()->seal(Keys::pair()->privateJwk);
        $tampered = $sealed;
        $tampered[strlen($tampered) - 1] = $tampered[strlen($tampered) - 1] === 'a' ? 'b' : 'a';

        $this->expectException(RuntimeException::class);
        Keys::sealer()->unseal($tampered);
    }

    #[Test]
    public function itRefusesGarbage(): void
    {
        $this->expectException(RuntimeException::class);

        Keys::sealer()->unseal('not an envelope');
    }
}
