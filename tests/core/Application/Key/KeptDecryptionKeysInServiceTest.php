<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\KeptDecryptionKeysInService;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldKeys;
use Beffroi\Core\Tests\Fixture\KeptEncryption;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3
 */
final class KeptDecryptionKeysInServiceTest extends TestCase
{
    #[Test]
    public function theKeysInServiceOfEachKeptHolderAreOpenedAndNoOtherKey(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant());
        $generator = new JwtLibraryKeyPairGenerator(Algorithms::everyUse());
        $keys->active(new KeptEncryption('a'), Keys::pair());
        $keys->staged(new KeptEncryption('a'), Keys::otherPair());
        $keys->active(new KeptEncryption('b'), $generator->generate(Algorithms::rsaOaep256()));
        $keys->retired(new KeptEncryption('b'), $generator->generate(Algorithms::rsaOaep256()));
        $keys->active(Algorithms::ecdhEsA256Kw(), Keys::encryptionPair());

        // When
        new KeptDecryptionKeysInService($keys->repository, $keys->provider)->open($keys->tenant);

        // Then
        static::assertSame(3, $keys->sealer->unsealed);
    }

    #[Test]
    public function theKeysOpenedAheadAreTheKeysAHolderAsksForWithoutTheKms(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant());
        $active = $keys->active(new KeptEncryption('a'), Keys::pair());
        $staged = $keys->staged(new KeptEncryption('a'), Keys::otherPair());
        new KeptDecryptionKeysInService($keys->repository, $keys->provider)->open($keys->tenant);

        // When
        $keys->provider->keptDecryptionKeys($keys->tenant, new KeptEncryption('a'), [$staged->kid, $active->kid]);

        // Then
        static::assertSame(2, $keys->sealer->unsealed);
    }
}
