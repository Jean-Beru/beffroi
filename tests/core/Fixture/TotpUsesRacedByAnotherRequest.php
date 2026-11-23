<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Port\TotpUsesInterface;
use Closure;
use DateTimeImmutable;

/**
 * Another request runs to its end between the checks of this one and its write, as it does on another worker.
 */
final class TotpUsesRacedByAnotherRequest implements TotpUsesInterface
{
    /**
     * @var (Closure(): void)|null
     */
    public ?Closure $anotherRequest = null;

    public function __construct(
        private readonly TotpUsesInterface $uses,
    ) {
    }

    public function acceptStep(TotpCredential $credential, int $step, DateTimeImmutable $now): bool
    {
        $this->letTheOtherRequestRun();

        return $this->uses->acceptStep($credential, $step, $now);
    }

    public function spendBackupCode(TotpCredential $credential, int $index, DateTimeImmutable $now): bool
    {
        $this->letTheOtherRequestRun();

        return $this->uses->spendBackupCode($credential, $index, $now);
    }

    private function letTheOtherRequestRun(): void
    {
        $request = $this->anotherRequest;
        $this->anotherRequest = null;
        if ($request !== null) {
            $request();
        }
    }
}
