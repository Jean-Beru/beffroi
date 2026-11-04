<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Unit;

use Beffroi\Xml\Enc\CbcContentAlgorithm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.1, E-1, E-15
 */
final class CbcContentAlgorithmTest extends TestCase
{
    /**
     * §9.3 row 24
     */
    #[Test]
    public function itNamesAes128CbcAndAes256Cbc(): void
    {
        // When / Then
        static::assertSame(
            [
                CbcContentAlgorithm::Aes128Cbc,
                CbcContentAlgorithm::Aes256Cbc,
                null,
                null,
            ],
            [
                CbcContentAlgorithm::tryFrom('http://www.w3.org/2001/04/xmlenc#aes128-cbc'),
                CbcContentAlgorithm::tryFrom('http://www.w3.org/2001/04/xmlenc#aes256-cbc'),
                CbcContentAlgorithm::tryFrom('http://www.w3.org/2001/04/xmlenc#aes192-cbc'),
                CbcContentAlgorithm::tryFrom('http://www.w3.org/2001/04/xmlenc#tripledes-cbc'),
            ],
        );
    }

    /**
     * §9.3 row 24, E-2
     */
    #[Test]
    public function itKnowsTheLengthOfItsKey(): void
    {
        // When / Then
        static::assertSame([16, 32], [CbcContentAlgorithm::Aes128Cbc->keyBytes(), CbcContentAlgorithm::Aes256Cbc->keyBytes()]);
    }

    /**
     * §9.3 row 24
     */
    #[Test]
    public function itKnowsItsOpensslCipher(): void
    {
        // When / Then
        static::assertSame(
            ['aes-128-cbc', 'aes-256-cbc'],
            [CbcContentAlgorithm::Aes128Cbc->cipher(), CbcContentAlgorithm::Aes256Cbc->cipher()],
        );
    }
}
