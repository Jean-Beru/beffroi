<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\RotationSchedule;
use Beffroi\Core\Port\RotationSchedulesInterface;

final readonly class FixedRotationSchedules implements RotationSchedulesInterface
{
    /**
     * @param array<string, RotationSchedule> $byAlgorithm
     */
    public function __construct(
        private RotationSchedule $schedule,
        private array $byAlgorithm = [],
    ) {
    }

    public function of(KeyAlgorithmInterface $algorithm): RotationSchedule
    {
        return $this->byAlgorithm[$algorithm->name()] ?? $this->schedule;
    }
}
