<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_shift;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Port\KeyPairGeneratorInterface;

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

    public function generate(KeyAlgorithmInterface $algorithm): GeneratedKeyPair
    {
        return array_shift($this->pairs) ?? throw new LogicException('No more precomputed key pairs.');
    }
}
