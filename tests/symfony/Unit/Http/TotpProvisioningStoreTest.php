<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use DateTimeImmutable;
use App\Http\TotpProvisioningSealer;
use App\Http\TotpProvisioningStore;
use Beffroi\Core\Domain\Credential\TotpProvisioning;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * Architecture §5.2, §3.3
 */
final class TotpProvisioningStoreTest extends TestCase
{
    private Session $session;

    private TotpProvisioningStore $store;

    private User $alice;

    private TotpProvisioning $provisioning;

    private DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->session = new Session(new MockArraySessionStorage());
        $this->store = new TotpProvisioningStore(new TotpProvisioningSealer(Totps::sealer()));
        $this->alice = Fixtures::user();
        $this->provisioning = new TotpProvisioning(Totps::secret(), Totps::algorithm()->provisioningUri(Totps::secret(), 'ACME', 'alice'), Totps::BACKUP_CODES);
        $this->now = new DateTimeImmutable('2026-09-20T10:00:00+00:00');
    }

    #[Test]
    public function theProvisioningIsReadBackWholeByTheUserItWasDrawnFor(): void
    {
        // Given
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);

        // When
        $read = $this->store->provisioning($this->session, $this->alice, $this->now->modify('+9 minutes'));

        // Then
        static::assertNotNull($read);
        static::assertSame(Totps::SEED, $read->secret->bytes);
        static::assertSame($this->provisioning->uri, $read->uri);
        static::assertSame(Totps::BACKUP_CODES, $read->backupCodes);
    }

    #[Test]
    public function itIsReadAgainUntilItIsForgotten(): void
    {
        // Given
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);
        $this->store->provisioning($this->session, $this->alice, $this->now);

        // When
        $again = $this->store->provisioning($this->session, $this->alice, $this->now);
        $this->store->forget($this->session);
        $afterwards = $this->store->provisioning($this->session, $this->alice, $this->now);

        // Then
        static::assertNotNull($again);
        static::assertNull($afterwards);
    }

    /**
     * Architecture §3.3
     */
    #[Test]
    public function whatTheSessionKeepsIsSealed(): void
    {
        // When
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);

        // Then
        $stored = serialize($this->session->get(TotpProvisioningStore::KEY));
        static::assertStringNotContainsString(Totps::SEED, $stored);
        static::assertStringNotContainsString('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $stored);
        static::assertStringNotContainsString('otpauth', $stored);
        static::assertStringNotContainsString(Totps::BACKUP_CODES[0], $stored);
    }

    #[Test]
    public function aProvisioningDrawnForSomeoneElseIsNullAndForgotten(): void
    {
        // Given
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);
        $bob = Fixtures::user(username: 'bob', subject: 'bob-subject');

        // When
        $read = $this->store->provisioning($this->session, $bob, $this->now);

        // Then
        static::assertNull($read);
        static::assertFalse($this->session->has(TotpProvisioningStore::KEY));
    }

    #[Test]
    public function anExpiredProvisioningIsNullAndForgotten(): void
    {
        // Given
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);

        // When
        $read = $this->store->provisioning($this->session, $this->alice, $this->now->modify('+10 minutes'));

        // Then
        static::assertNull($read);
        static::assertFalse($this->session->has(TotpProvisioningStore::KEY));
    }

    #[Test]
    public function aProvisioningSealedForAnotherTenantIsNullAndForgotten(): void
    {
        // Given
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);
        $elsewhere = Fixtures::user(Fixtures::tenant('globex', 'https://id.globex.example'));
        $stored = $this->session->get(TotpProvisioningStore::KEY);
        static::assertIsArray($stored);
        $this->session->set(TotpProvisioningStore::KEY, [
            'user' => $elsewhere->id->toRfc4122(),
            'expires_at' => $this->now->modify('+10 minutes')->getTimestamp(),
            'sealed' => $stored['sealed'],
        ]);

        // When
        $read = $this->store->provisioning($this->session, $elsewhere, $this->now);

        // Then
        static::assertNull($read);
        static::assertFalse($this->session->has(TotpProvisioningStore::KEY));
    }

    #[Test]
    public function nothingIsReadWhenNothingWasStored(): void
    {
        // When / Then
        static::assertNull($this->store->provisioning($this->session, $this->alice, $this->now));
    }

    #[Test]
    public function anOutageOfTheKmsGoesOnAsItCame(): void
    {
        // Given
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);

        // Then
        $this->expectException(KmsUnavailableException::class);

        // When
        $this->storeOnAKmsThatDoesNotAnswer()->provisioning($this->session, $this->alice, $this->now);
    }

    #[Test]
    public function theProvisioningWaitsForTheKmsToBeBack(): void
    {
        // Given
        $this->store->store($this->session, $this->alice, $this->provisioning, $this->now);
        try {
            $this->storeOnAKmsThatDoesNotAnswer()->provisioning($this->session, $this->alice, $this->now);
        } catch (KmsUnavailableException) {
        }

        // When
        $read = $this->store->provisioning($this->session, $this->alice, $this->now);

        // Then
        static::assertNotNull($read);
        static::assertSame(Totps::SEED, $read->secret->bytes);
    }

    private function storeOnAKmsThatDoesNotAnswer(): TotpProvisioningStore
    {
        $sealer = static::createStub(SecretSealerInterface::class);
        $sealer->method('unseal')->willThrowException(new KmsUnavailableException('The sealed secret could not be opened.'));

        return new TotpProvisioningStore(new TotpProvisioningSealer($sealer));
    }
}
