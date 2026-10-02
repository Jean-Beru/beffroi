<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\PersonalData;

use function bin2hex;
use DateTimeImmutable;

/**
 * One wrapped data key as a person is shown it: never its material, which the store holds wrapped and
 * which no reading of this kind opens.
 */
final readonly class StoredDataKeyDescription
{
    public function __construct(
        public string $reference,
        public ?DateTimeImmutable $mintedAt,
        public string $masterKeyId,
        public string $client,
    ) {
    }

    /**
     * The reference in the form the component prints it, which is what names a key in the output of
     * `key-management:rewrap-data-keys`.
     */
    public function hex(): string
    {
        return bin2hex($this->reference);
    }
}
