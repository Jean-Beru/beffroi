<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

/**
 * One thing the provider did during a request, as the panel shows it: the tab it belongs under, a
 * heading and the facts under it, in the order they are written. Whoever observes says where its
 * observation goes, what it is called and what it says, so that the panel renders an observation it has
 * never heard of, under a tab it has never heard of either, and no template enumerates the kinds.
 *
 * Everything here is meant to be read by a developer: no value of a token, of a secret, of a proof or of
 * a key ever reaches it, and what is personal data is named rather than given.
 */
final readonly class Observation
{
    /**
     * @param array<string, string> $entries by label, in the order they are shown
     */
    public function __construct(
        public string $tab,
        public string $heading,
        public array $entries,
    ) {
    }

    public function isSameAs(self $other): bool
    {
        return $this->tab === $other->tab && $this->heading === $other->heading && $this->entries === $other->entries;
    }
}
