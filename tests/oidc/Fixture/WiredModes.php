<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Port\ServedResponseModesInterface;

/**
 * The response modes a test wires exactly, including a wiring the bundle would never produce, such as
 * the same mode twice.
 */
final readonly class WiredModes implements ServedResponseModesInterface
{
    /**
     * @param non-empty-list<ResponseMode> $modes
     */
    private function __construct(
        private array $modes,
    ) {
    }

    /**
     * @param non-empty-list<ResponseMode> $modes
     */
    public static function of(array $modes): self
    {
        return new self($modes);
    }

    public function servedResponseModes(): array
    {
        return $this->modes;
    }
}
