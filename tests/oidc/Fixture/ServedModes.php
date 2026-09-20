<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Port\ServedResponseModesInterface;

/**
 * The response modes an integration wired: the default alone, as spike 1 had, or the default and the
 * posted form, as the bundle wires since spike 4.
 */
final readonly class ServedModes implements ServedResponseModesInterface
{
    /**
     * @param non-empty-list<ResponseMode> $modes
     */
    private function __construct(
        private array $modes,
    ) {
    }

    public static function queryOnly(): self
    {
        return new self([ResponseMode::Query]);
    }

    public static function queryAndFormPost(): self
    {
        return new self([ResponseMode::Query, ResponseMode::FormPost]);
    }

    public function servedResponseModes(): array
    {
        return $this->modes;
    }
}
