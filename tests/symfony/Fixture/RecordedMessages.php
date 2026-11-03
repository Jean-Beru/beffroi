<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Psr\Log\AbstractLogger;
use Stringable;

/**
 * What a class under test said, so that a test can read what an operator reads.
 *
 * A logger and not a mock: what these tests assert is the sentence itself, and a mock that verifies a call
 * says a call happened. The level is kept with the message because the level is what decides whether the
 * console prints it at all (`DoctrineCommand` maps notice to the normal verbosity and info to the verbose
 * one), so a sentence written at the wrong level is a sentence nobody reads.
 */
final class RecordedMessages extends AbstractLogger
{
    /**
     * The level as it was given, whatever it was: PSR-3 types it `mixed` and a test asks for the one it
     * expects, so nothing here decides what an unexpected level would have been.
     *
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
     * The messages written at one level, in the order they were written.
     *
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
