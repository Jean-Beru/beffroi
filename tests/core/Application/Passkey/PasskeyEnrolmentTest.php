<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Passkey;

use Heidi\Core\Application\Passkey\PasskeyEnrolment;
use Heidi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Credential\PasskeyUserHandle;
use Heidi\Core\Domain\Event\CredentialEnrolled;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Exception\CredentialEnrolmentFailedException;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\PasskeyCeremonyFailedException;
use Heidi\Core\Tests\Fixture\FakePasskeyRegistrar;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use stdClass;
use function strlen;
use Symfony\Component\Clock\MockClock;

/**
 * Architecture §3.4: a passkey enrolled from a session the user already holds, WebAuthn Level 3 §7.1.
 */
final class PasskeyEnrolmentTest extends TestCase
{
    private User $alice;

    private InMemoryCredentialRepository $credentials;

    private FakePasskeyRegistrar $registrar;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private PasskeyEnrolment $enrolment;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->credentials = new InMemoryCredentialRepository();
        $this->registrar = new FakePasskeyRegistrar();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-19T12:00:00+00:00');
        $this->enrolment = new PasskeyEnrolment($this->credentials, $this->registrar, $this->clock, $this->events);
    }

    #[Test]
    public function itEnrolsPasskeys(): void
    {
        // When / Then
        static::assertSame(PasskeyCredential::class, $this->enrolment->kind());
    }

    #[Test]
    public function aChallengeThatIsNotCreationOptionsIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The challenge of a passkey enrolment is its creation options.');

        // When
        $this->enrolment->complete($this->alice, 'Pixel', new stdClass(), '{}', Fixtures::context()); // @phpstan-ignore argument.type (the contract is broken on purpose)
    }

    #[Test]
    public function aFirstPasskeyGetsAFreshHandleAndExcludesNothing(): void
    {
        // When
        $options = $this->enrolment->begin($this->alice);

        // Then
        static::assertSame(PasskeyUserHandle::LENGTH, strlen($options->user->id));
        static::assertSame('alice', $options->user->name);
        static::assertSame([], $options->excludeCredentials);
    }

    /**
     * WebAuthn Level 3 §14.6.1: one handle per user, whatever the number of passkeys.
     */
    #[Test]
    public function aSecondPasskeyReusesTheHandleAndExcludesTheFirstEvenRevoked(): void
    {
        // Given
        $first = Fixtures::passkey($this->alice, credentialId: 'first');
        $first->revoke(Fixtures::now());
        $this->credentials->save($first);

        // When
        $options = $this->enrolment->begin($this->alice);

        // Then
        static::assertSame($first->userHandle->value, $options->user->id);
        static::assertCount(1, $options->excludeCredentials);
        static::assertSame('first', $options->excludeCredentials[0]->id);
    }

    #[Test]
    public function aVerifiedRecordBecomesAPasskeyOfTheUserAndIsAnnounced(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->registrar->returns(FakePasskeyRegistrar::record($options, 'new-credential', backupEligible: true, backedUp: true));
        $context = Fixtures::context($this->clock->now());

        // When
        $passkey = $this->enrolment->complete($this->alice, 'Pixel', $options, '{"id":"new-credential"}', $context);

        // Then
        static::assertSame($this->alice, $passkey->user);
        static::assertSame('Pixel', $passkey->name);
        static::assertSame('new-credential', $passkey->credentialId);
        static::assertSame($options->user->id, $passkey->userHandle->value);
        static::assertTrue($passkey->backupEligible);
        static::assertEquals($this->clock->now(), $passkey->createdAt);
        static::assertSame([$passkey], $this->credentials->findByUser($this->alice, PasskeyCredential::class));
        $events = $this->events->of(CredentialEnrolled::class);
        static::assertCount(1, $events);
        static::assertSame($passkey, $events[0]->credential);
        static::assertSame($context, $events[0]->context);
        static::assertSame($this->alice->tenant, $events[0]->tenant);
    }

    #[Test]
    public function aRefusedCeremonyFailsTheEnrolmentWithItsCause(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->registrar->refuses('The origin does not match.');

        // When
        try {
            $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
            static::fail('The enrolment should have failed.');
        } catch (CredentialEnrolmentFailedException $exception) {
            // Then
            static::assertSame('The origin does not match.', $exception->getMessage());
            static::assertInstanceOf(PasskeyCeremonyFailedException::class, $exception->getPrevious());
        }
    }

    #[Test]
    public function aRefusedCeremonyEnrolsNothing(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->registrar->refuses('The origin does not match.');

        // When
        try {
            $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
        } catch (CredentialEnrolmentFailedException) {
        }

        // Then
        static::assertSame([], $this->credentials->findByUser($this->alice));
        static::assertSame([], $this->events->events);
    }

    /**
     * WebAuthn Level 3 §7.1, step 26.
     */
    #[Test]
    public function aCredentialIdKnownInTheTenantIsRefused(): void
    {
        // Given
        $options = $this->enrolment->begin($this->alice);
        $this->credentials->save(Fixtures::passkey(Fixtures::user($this->alice->tenant, 'bob', 'bob-subject'), credentialId: 'taken'));
        $this->registrar->returns(FakePasskeyRegistrar::record($options, 'taken'));

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('This passkey is enrolled already.');

        // When
        $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
    }

    #[Test]
    public function optionsDrawnForAnotherUserAreRefused(): void
    {
        // Given
        $this->credentials->save(Fixtures::passkey($this->alice, credentialId: 'first'));
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');
        $options = $this->enrolment->begin($bob);

        // Then
        $this->expectException(CredentialEnrolmentFailedException::class);
        $this->expectExceptionMessageIs('The options were not drawn for this user.');

        // When
        $this->enrolment->complete($this->alice, 'Pixel', $options, '{}', Fixtures::context());
    }
}
