<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\PublishedDecryptionKeys;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldKeys;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3, RFC 7516 §4.1.6
 */
final class PublishedDecryptionKeysTest extends TestCase
{
    #[Test]
    public function eachPublishedEncryptionKeyIsOpenedAndNoOtherKey(): void
    {
        // Given
        $keys = new HeldKeys(Fixtures::tenant());
        $generator = new JwtLibraryKeyPairGenerator(Algorithms::everyUse());
        $keys->active(Algorithms::ecdhEsA256Kw(), Keys::encryptionPair());
        $keys->staged(Algorithms::ecdhEsA256Kw(), $generator->generate(Algorithms::ecdhEsA256Kw()));
        $keys->retired(Algorithms::ecdhEsA256Kw(), $generator->generate(Algorithms::ecdhEsA256Kw()));
        $keys->active(Algorithms::rs256(), Keys::pair());
        $keys->active(Algorithms::messageSeal(), Keys::messagePair());

        // When
        new PublishedDecryptionKeys($keys->provider, $keys->provider)->open($keys->tenant);

        // Then
        static::assertSame(2, $keys->sealer->unsealed);
    }
}
