<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use function array_shift;
use Heidi\Core\Domain\Key\GeneratedKeyPair;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\KeyPairGeneratorInterface;

/**
 * Hands out pre-generated pairs: generating RSA keys in every test would cost seconds for nothing.
 */
final class PrecomputedKeyPairGenerator implements KeyPairGeneratorInterface
{
    /**
     * @param list<GeneratedKeyPair> $pairs
     */
    public function __construct(
        private array $pairs,
    ) {
    }

    public function generate(SignatureAlgorithmInterface $algorithm): GeneratedKeyPair
    {
        return array_shift($this->pairs) ?? throw new LogicException('No more precomputed key pairs.');
    }
}
