<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Tenant;

use function array_map;
use function iterator_to_array;
use Beffroi\Core\Application\Tenant\TenantHardening;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantRepository;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Event\CredentialForgotten;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationPredicate;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\Totps;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #327: a tenant names the floor of its logins, and what the floor forbids leaves the model. The
 * act is the one an administrator presses from a command or from the console, and both press this.
 */
final class TenantHardeningTest extends TestCase
{
    private Tenant $tenant;

    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private InMemoryTenantRepository $tenants;

    private RecordingEventDispatcher $events;

    private RequestContext $context;

    private TenantHardening $hardening;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->credentials = new InMemoryCredentialRepository();
        $this->tenants = new InMemoryTenantRepository();
        $this->events = new RecordingEventDispatcher();
        $clock = new MockClock('2026-10-11T12:00:00+00:00');
        $this->context = Fixtures::context($clock->now());
        $this->hardening = new TenantHardening($this->tenants, $this->credentials, $clock, $this->events);
    }

    #[Test]
    public function theTenantKeepsTheFloorItWasGiven(): void
    {
        // When
        $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistant, $this->context);

        // Then
        static::assertSame(AuthenticationPredicate::PhishingResistant, $this->tenant->loginFloor);
        static::assertSame([$this->tenant->id->toRfc4122() => $this->tenant], $this->tenants->tenants);
    }

    /**
     * The password, the TOTP and the backup codes it holds go together: none of them proves anything a
     * phishing-resistant floor reads, so none of them is left in the store (CredentialForgotten).
     */
    #[Test]
    public function whatTheFloorForbidsIsForgottenAndTheActIsAnnounced(): void
    {
        // Given
        $password = Fixtures::password($this->alice);
        $totp = Totps::credential($this->alice, new FakePasswordHasher());
        $passkey = Fixtures::passkey($this->alice);
        foreach ([$password, $totp, $passkey] as $credential) {
            $this->credentials->save($credential);
        }

        // When
        $forgotten = $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistant, $this->context);

        // Then
        static::assertSame(2, $forgotten);
        static::assertSame([$passkey], $this->credentials->findByUser($this->alice));
        static::assertSame(
            [PasswordCredential::class, TotpCredential::class],
            array_map(static fn (CredentialForgotten $act): string => $act->credential::class, $this->events->of(CredentialForgotten::class)),
        );
    }

    /**
     * A key bound to its authenticator stays under a floor that asks for one, and a synced passkey does
     * not: what the floor reads is what the attestation said of the key, never the kind.
     */
    #[Test]
    public function aFloorThatAsksForHardwareForgetsASyncedPasskey(): void
    {
        // Given
        $synced = Fixtures::passkey($this->alice, 'The phone', 'synced-id', backupEligible: true, backedUp: true);
        $bound = Fixtures::passkey($this->alice, 'YubiKey 5', 'bound-id');
        foreach ([$synced, $bound] as $credential) {
            $this->credentials->save($credential);
        }

        // When
        $forgotten = $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistantHardware, $this->context);

        // Then
        static::assertSame(1, $forgotten);
        static::assertSame([$bound], $this->credentials->findByUser($this->alice, PasskeyCredential::class));
    }

    /**
     * A revoked credential proves nothing already, so the floor forbids nothing about it and the page of
     * that person keeps naming it.
     */
    #[Test]
    public function aRevokedCredentialIsLeftWhereItIs(): void
    {
        // Given
        $totp = Totps::credential($this->alice, new FakePasswordHasher());
        $totp->revoke(Fixtures::now());
        $this->credentials->save($totp);

        // When
        $forgotten = $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistant, $this->context);

        // Then
        static::assertSame(0, $forgotten);
        static::assertSame([$totp], $this->credentials->findByUser($this->alice));
    }

    /**
     * The credentials of another tenant are another tenant's business, the walk reading one tenant.
     */
    #[Test]
    public function thePasswordOfAnotherTenantIsNotTouched(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $elsewhere = Fixtures::password(Fixtures::user($other, 'bob', 'bob-subject'));
        $this->credentials->save($elsewhere);
        $this->credentials->save(Fixtures::password($this->alice));

        // When
        $forgotten = $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistant, $this->context);

        // Then
        static::assertSame(1, $forgotten);
        static::assertSame([$elsewhere], iterator_to_array($this->credentials->credentialsOf($other), false));
    }

    /**
     * Named twice, it forgets nothing twice: the sweep is the one an interruption is run through again.
     */
    #[Test]
    public function theSameFloorNamedAgainForgetsNothingMore(): void
    {
        // Given
        $this->credentials->save(Fixtures::password($this->alice));
        $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistant, $this->context);

        // When
        $forgotten = $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistant, $this->context);

        // Then
        static::assertSame(0, $forgotten);
        static::assertCount(1, $this->events->of(CredentialForgotten::class));
    }

    /**
     * A tenant that lowers its floor again holds no password of anybody: what was forgotten is gone, and
     * the single factor admits what it always did for whoever poses one.
     */
    #[Test]
    public function loweringTheFloorGivesNobodyBackWhatWasForgotten(): void
    {
        // Given
        $this->credentials->save(Fixtures::password($this->alice));
        $this->hardening->adopt($this->tenant, AuthenticationPredicate::PhishingResistant, $this->context);

        // When
        $this->hardening->adopt($this->tenant, AuthenticationPredicate::SingleFactor, $this->context);

        // Then
        static::assertSame(AuthenticationPredicate::SingleFactor, $this->tenant->loginFloor);
        static::assertSame([], $this->credentials->findByUser($this->alice));
    }
}
