<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Key;

use Beffroi\Core\Application\Key\ActiveSigningKeys;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\EnvelopesThatThrow;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldKeys;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\Exception\RuntimeException;

/**
 * Architecture §3.3
 */
final class ActiveSigningKeysTest extends TestCase
{
    private HeldKeys $keys;

    protected function setUp(): void
    {
        $this->keys = new HeldKeys(Fixtures::tenant());
    }

    #[Test]
    public function theActiveKeyOfEachWiredAlgorithmIsOpened(): void
    {
        // Given
        $this->keys->active(Algorithms::rs256(), Keys::pair());
        $this->keys->active(Algorithms::es256(), new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::es256()));
        $this->keys->staged(Algorithms::rs256(), Keys::otherPair());

        // When
        new ActiveSigningKeys(Algorithms::all(), $this->keys->provider)->open($this->keys->tenant);

        // Then
        static::assertSame(2, $this->keys->sealer->unsealed);
    }

    #[Test]
    public function aKeyOpenedAheadSignsWithoutAskingTheKms(): void
    {
        // Given
        $this->keys->active(Algorithms::rs256(), Keys::pair());
        new ActiveSigningKeys(Algorithms::all(), $this->keys->provider)->open($this->keys->tenant);

        // When
        $this->keys->provider->activeKey($this->keys->tenant, Algorithms::rs256());

        // Then
        static::assertSame(1, $this->keys->sealer->unsealed);
    }

    #[Test]
    public function anAlgorithmWithNoActiveKeyLeavesTheNextOneOpened(): void
    {
        // Given
        $this->keys->active(Algorithms::es256(), new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate(Algorithms::es256()));

        // When
        new ActiveSigningKeys(Algorithms::all(), $this->keys->provider)->open($this->keys->tenant);

        // Then
        static::assertSame(1, $this->keys->sealer->unsealed);
    }

    #[Test]
    public function aKmsThatDoesNotAnswerIsAnOutage(): void
    {
        // Given
        $this->keys->active(Algorithms::rs256(), Keys::pair());
        $provider = new SealedKeyProvider(
            $this->keys->repository,
            new OpenedKeys(new EnvelopeKeySealer(new EnvelopesThatThrow(new RuntimeException('Failed to reach the KMS.')), Keys::KMS_KEY_ID)),
        );

        // Then
        $this->expectException(KmsUnavailableException::class);

        // When
        new ActiveSigningKeys(Algorithms::all(), $provider)->open($this->keys->tenant);
    }
}
