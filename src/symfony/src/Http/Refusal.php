<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

/**
 * What a page says of a form it refused (issue #481): the code it translates, and the field the refusal is
 * about when it is about one.
 *
 * A code and never a sentence, as every other refusal of these pages is, so that an application renders it
 * in its own words and in the language of whoever reads it. And never the value a person typed: a refusal
 * crosses a redirection in the session of the browser, and a session is a disk.
 */
final readonly class Refusal
{
    public function __construct(
        public string $code,
        public ?string $field = null,
    ) {
    }
}
