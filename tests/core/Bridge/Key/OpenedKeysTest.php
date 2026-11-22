<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Key;

use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0018, Architecture §3.3, RFC 7638, RFC 7517 §4.5
 */
final class OpenedKeysTest extends TestCase
{
    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    #[Test]
    public function aKeyIsOpenedOnceAndHandedBackAsItIs(): void
    {
        // Given
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::once())->method('unseal')->willReturn(Keys::pair()->privateJwk);
        $keys = new OpenedKeys($sealer);
        $key = $this->key(Algorithms::rs256(), Keys::pair());

        // When
        $opened = $keys->open($this->tenant, $key);

        // Then
        static::assertSame($opened, $keys->open($this->tenant, $key));
    }

    #[Test]
    public function aKeyThatWasForgottenIsOpenedAgain(): void
    {
        // Given
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::exactly(2))->method('unseal')->willReturn(Keys::pair()->privateJwk);
        $keys = new OpenedKeys($sealer);
        $key = $this->key(Algorithms::rs256(), Keys::pair());
        $opened = $keys->open($this->tenant, $key);

        // When
        $keys->forget($this->tenant, $key->kid);

        // Then
        static::assertNotSame($opened, $keys->open($this->tenant, $key));
    }

    /**
     * RFC 7517 §4.5
     */
    #[Test]
    public function forgettingTheKeyOfOneTenantLeavesTheKeyOfAnotherUnderThatNameOpen(): void
    {
        // Given
        $keys = new OpenedKeys($this->sealer());
        $globex = Fixtures::tenant('globex', 'https://id.globex.example');
        $sameName = self::keyOf($globex, Algorithms::rs256(), Keys::pair());
        $opened = $keys->open($globex, $sameName);

        // When
        $keys->forget($this->tenant, $sameName->kid);

        // Then
        static::assertSame($opened, $keys->open($globex, $sameName));
    }

    #[Test]
    public function theOtherKeysOfThatTenantAndThatAlgorithmAreForgotten(): void
    {
        // Given
        $keys = new OpenedKeys($this->sealer());
        $previous = $this->key(Algorithms::rs256(), Keys::pair());
        $answered = $this->key(Algorithms::rs256(), Keys::otherPair());
        $opened = $keys->open($this->tenant, $previous);
        $keys->open($this->tenant, $answered);

        // When
        $keys->forgetOthers($this->tenant, $answered);

        // Then
        static::assertNotSame($opened, $keys->open($this->tenant, $previous));
    }

    #[Test]
    public function theKeyAnsweredWithStaysOpen(): void
    {
        // Given
        $keys = new OpenedKeys($this->sealer());
        $answered = $this->key(Algorithms::rs256(), Keys::otherPair());
        $keys->open($this->tenant, $this->key(Algorithms::rs256(), Keys::pair()));
        $opened = $keys->open($this->tenant, $answered);

        // When
        $keys->forgetOthers($this->tenant, $answered);

        // Then
        static::assertSame($opened, $keys->open($this->tenant, $answered));
    }

    /**
     * Decision 0020
     */
    #[Test]
    public function aKeyOfAnotherAlgorithmOfThatTenantStaysOpen(): void
    {
        // Given
        $keys = new OpenedKeys($this->sealer());
        $message = $this->key(Algorithms::messageSeal(), Keys::messagePair());
        $opened = $keys->open($this->tenant, $message);

        // When
        $keys->forgetOthers($this->tenant, $this->key(Algorithms::rs256(), Keys::pair()));

        // Then
        static::assertSame($opened, $keys->open($this->tenant, $message));
    }

    #[Test]
    public function theKeyOfAnotherTenantOfThatAlgorithmStaysOpen(): void
    {
        // Given
        $keys = new OpenedKeys($this->sealer());
        $globex = Fixtures::tenant('globex', 'https://id.globex.example');
        $elsewhere = self::keyOf($globex, Algorithms::rs256(), Keys::otherPair());
        $opened = $keys->open($globex, $elsewhere);

        // When
        $keys->forgetOthers($this->tenant, $this->key(Algorithms::rs256(), Keys::pair()));

        // Then
        static::assertSame($opened, $keys->open($globex, $elsewhere));
    }

    private function sealer(): KeySealerInterface
    {
        $sealer = static::createStub(KeySealerInterface::class);
        $sealer->method('unseal')->willReturn(Keys::pair()->privateJwk);

        return $sealer;
    }

    private function key(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        return self::keyOf($this->tenant, $algorithm, $pair);
    }

    private static function keyOf(Tenant $tenant, KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        return new TenantKey(
            $pair->kid,
            $tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
    }
}
