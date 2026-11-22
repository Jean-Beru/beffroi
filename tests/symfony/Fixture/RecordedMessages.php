<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Psr\Log\AbstractLogger;
use Stringable;

final class RecordedMessages extends AbstractLogger
{
    /**
     * @var list<array{mixed, string}>
     */
    private array $records = [];

    /**
     * @param array<mixed> $context
     */
    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [$level, (string) $message];
    }

    /**
     * @return list<string>
     */
    public function at(string $level): array
    {
        $messages = [];
        foreach ($this->records as [$recorded, $message]) {
            if ($recorded === $level) {
                $messages[] = $message;
            }
        }

        return $messages;
    }
}
