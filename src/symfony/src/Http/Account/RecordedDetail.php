<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\Account;

use DateTimeImmutable;

/**
 * One thing this provider holds about a person, as the page of their information reads it (architecture
 * §5.2): the key its label is translated under, and the value in the shape the page renders it, a string
 * or a moment, with whether it has been verified when it is a contact detail (OIDC Core §5.1).
 *
 * Three kinds of value and not a type read at the template: what a detail is, it says here.
 */
final readonly class RecordedDetail
{
    private function __construct(
        public string $key,
        public ?string $value,
        public ?DateTimeImmutable $moment,
        public ?bool $verified,
    ) {
    }

    public static function said(string $key, string $value): self
    {
        return new self($key, $value, null, null);
    }

    /**
     * A contact detail, which this provider has either verified or not; nothing else carries that state.
     */
    public static function verifiable(string $key, string $value, bool $verified): self
    {
        return new self($key, $value, null, $verified);
    }

    public static function dated(string $key, DateTimeImmutable $moment): self
    {
        return new self($key, null, $moment, null);
    }
}
