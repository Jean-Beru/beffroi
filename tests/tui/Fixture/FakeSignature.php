<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use Beffroi\Tui\Update\SelfUpdateException;
use Beffroi\Tui\Update\SignatureVerifierInterface;

/**
 * A verifier that vouches for every signature, or for none.
 */
final readonly class FakeSignature implements SignatureVerifierInterface
{
    public const string REFUSAL = 'The signature vouches for nothing.';

    private function __construct(
        private bool $vouches,
    ) {
    }

    public static function vouching(): self
    {
        return new self(true);
    }

    public static function refusing(): self
    {
        return new self(false);
    }

    public function verify(string $signedFile, string $signatureFile): void
    {
        if (! $this->vouches) {
            throw new SelfUpdateException(self::REFUSAL);
        }
    }
}
