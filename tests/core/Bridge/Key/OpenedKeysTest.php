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
 * Decision 0018, architecture §3.3: the private half a process holds open is asked of the KMS once and
 * kept for as long as it answers, which is what keeps the KMS off the path of a request. The other half of
 * that bargain is forgetting, and it is what is asserted here one gesture at a time, the memory being the
 * only place where it shows.
 *
 * What is held is ranged by tenant and by "kid" both (RFC 7638, RFC 7517 §4.5): the name alone does not
 * say whose key it is, so neither forgetting answers for a tenant that was not named.
 */
final class OpenedKeysTest extends TestCase
{
    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * The KMS is asked once, and what every caller afterwards is handed is the material of that one
     * opening.
     */
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

    /**
     * And a key that was forgotten is asked of the KMS again: what is answered afterwards is the material
     * of a second opening and not of the first.
     */
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
     * RFC 7517 §4.5: the "kid" names a key, it does not say whose. Two tenants that hold the same material
     * name it the same, and forgetting the key of one leaves the key of the other open.
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

    /**
     * A tenant holds one key per algorithm that answers, so the key that stopped answering for it is out
     * of the process: the private half of a key that signs nothing any more has no reason to stay.
     */
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

    /**
     * The one answered with is the one worth keeping open, and it is kept: a rotation seen by a worker
     * costs the opening of the new key and no more.
     */
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
     * Decision 0020: the key a tenant seals what leaves the process to is of another algorithm and answers
     * another question, so what a signature rotation leaves behind is not it. A worker holds that one for
     * every message of its vintage.
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

    /**
     * And a rotation is the rotation of one tenant: what another tenant holds open is none of its
     * business, whatever the algorithm.
     */
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

    /**
     * A sealer that opens whatever it is handed: what is asserted above is which key is in memory and
     * never the material, which nothing of these tests reads.
     */
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

    /**
     * A key of that tenant, staged, the memory caring no more about its status than about its material.
     */
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
