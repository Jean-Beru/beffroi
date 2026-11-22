<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Enc\Support;

use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\OaepHash;

/**
 * Section 5.2
 */
final class UnwrappingKey implements DecryptionKeyInterface
{
    public ?string $wrapped = null;

    public ?OaepHash $hash = null;

    public function __construct(
        private readonly ?string $answer,
    ) {
    }

    public function unwrap(string $wrapped, OaepHash $hash): ?string
    {
        $this->wrapped = $wrapped;
        $this->hash = $hash;

        return $this->answer;
    }
}
