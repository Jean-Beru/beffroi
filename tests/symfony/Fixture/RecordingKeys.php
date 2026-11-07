<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\OpenableKeysInterface;
use Throwable;

final class RecordingKeys implements OpenableKeysInterface
{
    /**
     * @var list<string> the slug of each tenant they were opened for
     */
    public private(set) array $openedFor = [];

    public function __construct(
        private readonly ?Throwable $refusal = null,
    ) {
    }

    public function open(Tenant $tenant): void
    {
        $this->openedFor[] = $tenant->slug;
        if ($this->refusal !== null) {
            throw $this->refusal;
        }
    }
}
