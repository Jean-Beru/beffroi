<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function in_array;
use Beffroi\Oidc\Domain\Authorization\ResponseModeNames;
use Beffroi\Oidc\Port\ServedResponseModesInterface;

final readonly class WiredModes implements ServedResponseModesInterface
{
    /**
     * @param non-empty-list<string> $modes
     * @param list<string> $signing
     */
    private function __construct(
        private array $modes,
        private array $signing,
        private ?string $alias,
    ) {
    }

    /**
     * @param non-empty-list<string> $modes
     * @param list<string> $signing
     */
    public static function of(array $modes, array $signing = [], ?string $alias = null): self
    {
        return new self($modes, $signing, $alias);
    }

    public function servedResponseModes(): array
    {
        return $this->modes;
    }

    public function responseModeNamed(string $requested): ?string
    {
        if ($requested === ResponseModeNames::ALIAS) {
            return $this->alias;
        }

        return in_array($requested, $this->modes, true) ? $requested : null;
    }

    public function signsAnyAnswer(): bool
    {
        return $this->signing !== [];
    }
}
