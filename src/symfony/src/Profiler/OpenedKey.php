<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use Heidi\Core\Domain\Key\UnsealedKey;

/**
 * What the panel says of a key the KMS opened during the request, written once for the two providers
 * that open one: the key that signs and the key that opens what a client sealed.
 */
final readonly class OpenedKey
{
    public static function observe(UnsealedKey $unsealed, string $purpose, KmsBackend $kms): Observation
    {
        return new Observation('Key', [
            'kid' => $unsealed->key->kid,
            'algorithm' => $unsealed->key->algorithm->name(),
            'use' => $unsealed->key->algorithm->keyUse()->value,
            'what it does here' => $purpose,
            'status' => $unsealed->key->status->value,
            'opened by' => $kms->name(),
        ]);
    }
}
