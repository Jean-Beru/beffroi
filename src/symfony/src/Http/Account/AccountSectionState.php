<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

/**
 * What a section says of an account: a key the home page translates and the parameters of its message. A
 * section always says something, an account that holds nothing there included, so that a line of the page
 * is never empty.
 */
final readonly class AccountSectionState
{
    /**
     * @param array<string, string|int> $parameters
     */
    public function __construct(
        public string $key,
        public array $parameters = [],
    ) {
    }
}
