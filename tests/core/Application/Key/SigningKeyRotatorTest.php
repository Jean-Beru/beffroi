<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Key;

use function array_shift;
use function array_values;
use DateInterval;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Event\SigningKeyRetired;
use Heidi\Core\Domain\Event\SigningKeyRotated;
use Heidi\Core\Domain\Event\SigningKeyStaged;
use Heidi\Core\Domain\Key\GeneratedKeyPair;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\RetirementReason;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Exception\RetirementNotDueException;
use Heidi\Core\Port\IssuedJwsKindInterface;
use Heidi\Core\Port\KeyPairGeneratorInterface;
use Heidi\Core\Tests\Fixture\FixedLifetimeJwsKind;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Clock\MockClock;

/**
 * The rotation of spike 2 (OIDC Core §10.1.1, architecture §3.3): the new key is published before it
 * signs, the previous one stays published while a JWS it signed can be alive, then leaves the JWK Set
 * when its retirement date has passed; a compromised key leaves at once.
 */
final class SigningKeyRotatorTest extends TestCase
{
    /**
     * The kinds of JWS the tenant issues under test: ten minutes and one hour, so that the longest wins.
     */
    private const string LONGEST_LIFETIME = 'PT1H';

    /**
     * The staging window under test: six minutes, the JWKS max-age of five plus the refetch cooldown.
     */
    private const string STAGING_DELAY = 'PT6M';

    private Tenant $tenant;

    private InMemorySigningKeyRepository $repository;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private RequestContext $context;

    private SigningKeyRotator $rotator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->repository = new InMemorySigningKeyRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T14:00:00+00:00');
        $this->context = RequestContext::unknown($this->clock->now());
        $this->rotator = $this->rotator([new FixedLifetimeJwsKind(new DateInterval('PT10M')), new FixedLifetimeJwsKind(new DateInterval(self::LONGEST_LIFETIME))]);
    }

    #[Test]
    public function theFirstRotationActivatesAKeyAtOnceAndRetiresNothing(): void
    {
        // When
        $first = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertSame(Keys::pair()->kid, $first->kid);
        static::assertTrue($first->isActive());
        static::assertEquals($this->clock->now(), $first->activatedAt);
        static::assertSame($first, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
        static::assertNull($this->events->of(SigningKeyRotated::class)[0]->retiring);
    }

    /**
     * The staging window: the key is in the JWK Set, and the one that was active still signs.
     */
    #[Test]
    public function stagingPublishesAKeyThatDoesNotSign(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertSame(KeyStatus::Staged, $staged->status);
        static::assertEquals($this->clock->now(), $staged->createdAt);
        static::assertSame([$first, $staged], $this->repository->findPublished($this->tenant));
        static::assertSame($first, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
    }

    /**
     * The staging window ends after the configured delay: the date is written on the key.
     */
    #[Test]
    public function stagingDatesTheActivationAfterTheStagingDelay(): void
    {
        // When
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertEquals($this->clock->now()->add(new DateInterval(self::STAGING_DELAY)), $staged->activationDueAt);
    }

    /**
     * Nothing to wait for when the key signs at once.
     */
    #[Test]
    public function aRotationDatesTheActivationAtOnce(): void
    {
        // When
        $key = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertEquals($this->clock->now(), $key->activationDueAt);
    }

    #[Test]
    public function stagingSealsThePrivateKeyForTheTenant(): void
    {
        // When
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertSame(Keys::pair()->privateJwk, Keys::sealer()->unseal($this->tenant, $staged->sealedPrivateJwk));
    }

    #[Test]
    public function stagingAnnouncesTheKey(): void
    {
        // When
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        [$event] = $this->events->of(SigningKeyStaged::class);
        static::assertSame($staged, $event->staged);
        static::assertSame($this->tenant, $event->tenant);
        static::assertSame($this->context, $event->context);
        static::assertSame([], $this->events->of(SigningKeyRotated::class));
    }

    #[Test]
    public function activatingAStagedKeyMakesItSign(): void
    {
        // Given
        $this->firstRotation();
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $activated = $this->rotator->activate($this->tenant, $staged->kid, $this->context);

        // Then
        static::assertSame($staged, $activated);
        static::assertTrue($activated->isActive());
        static::assertEquals($this->clock->now(), $activated->activatedAt);
        static::assertSame($activated, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
        static::assertSame(Keys::otherPair()->privateJwk, new SealedKeyProvider($this->repository, Keys::sealer())->activeKey($this->tenant, SignatureAlgorithm::RS256)->privateJwk);
    }

    /**
     * The timed step of the staging window: a key past its activation date is activated, and not before.
     */
    #[Test]
    public function activateDueActivatesAKeyPastItsActivationDate(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $activated = $this->rotator->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([$staged], $activated);
        static::assertTrue($staged->isActive());
        static::assertEquals($this->clock->now(), $staged->activatedAt);
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame($staged, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
    }

    #[Test]
    public function activateDueLeavesAKeyInsideItsStagingWindow(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+5 minutes 59 seconds');
        $savesBefore = $this->repository->saves;

        // When
        $activated = $this->rotator->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $activated);
        static::assertSame(KeyStatus::Staged, $staged->status);
        static::assertSame($savesBefore, $this->repository->saves);
        static::assertSame($first, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
    }

    /**
     * Two keys due in the same tick: both are activated in creation order, the last one signs.
     */
    #[Test]
    public function activateDueActivatesEveryDueKeyTheLastOneSigning(): void
    {
        // Given
        $first = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+1 second');
        $second = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $activated = $this->rotator->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([$first, $second], $activated);
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame($second, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
    }

    #[Test]
    public function activateDueAnnouncesTheRotation(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+1 hour');

        // When
        $this->rotator->activateDue($this->tenant, $this->context);

        // Then
        $event = $this->events->of(SigningKeyRotated::class)[1];
        static::assertSame($staged, $event->activated);
        static::assertSame($first, $event->retiring);
        static::assertSame($this->context, $event->context);
    }

    #[Test]
    public function activateDueDoesNothingWithoutAStagedKey(): void
    {
        // Given
        $this->firstRotation();
        $savesBefore = $this->repository->saves;

        // When
        $activated = $this->rotator->activateDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $activated);
        static::assertSame($savesBefore, $this->repository->saves);
        static::assertCount(1, $this->events->of(SigningKeyRotated::class));
    }

    /**
     * The retirement window opens: the previous key is due once the longest JWS the tenant issues, signed
     * a moment before the activation, has expired.
     */
    #[Test]
    public function activatingAStagedKeyStartsRetiringTheActiveOne(): void
    {
        // Given
        $first = $this->firstRotation();
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+6 minutes');

        // When
        $this->rotator->activate($this->tenant, $staged->kid, $this->context);

        // Then
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertEquals($this->clock->now(), $first->retiringAt);
        static::assertEquals($this->clock->now()->add(new DateInterval(self::LONGEST_LIFETIME)), $first->retirementDueAt);
        static::assertSame([$first, $staged], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function theRetirementDateIgnoresAKindOfJwsTheTenantDoesNotIssue(): void
    {
        // Given
        $rotator = $this->rotator([new FixedLifetimeJwsKind(new DateInterval('PT10M')), new FixedLifetimeJwsKind(null)]);
        $first = $rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // When
        $rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertEquals($this->clock->now()->modify('+10 minutes'), $first->retirementDueAt);
    }

    #[Test]
    public function aTenantThatIssuesNoJwsRetiresItsKeyAtOnce(): void
    {
        // Given
        $rotator = $this->rotator([]);
        $first = $rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // When
        $rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertEquals($this->clock->now(), $first->retirementDueAt);
        static::assertTrue($first->isDue($this->clock->now()));
    }

    #[Test]
    public function activatingTheActiveKeyFails(): void
    {
        // Given
        $first = $this->firstRotation();

        // Then
        $this->expectException(LogicException::class);

        // When
        $this->rotator->activate($this->tenant, $first->kid, $this->context);
    }

    #[Test]
    public function activatingAnUnknownKeyFails(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->rotator->activate($this->tenant, 'nope', $this->context);
    }

    #[Test]
    public function aRotationActivatesTheNewKey(): void
    {
        // Given
        $this->firstRotation();

        // When
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertSame(Keys::otherPair()->kid, $second->kid);
        static::assertSame($second, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
    }

    #[Test]
    public function aRotationStartsRetiringThePreviousKeyAndKeepsItPublished(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertEquals($this->clock->now(), $first->retiringAt);
        static::assertEquals($this->clock->now()->add(new DateInterval(self::LONGEST_LIFETIME)), $first->retirementDueAt);
        static::assertSame([$first, $second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function aRotationSavesTheStagedKeyThenBothKeys(): void
    {
        // Given
        $this->firstRotation();
        $savesBefore = $this->repository->saves;

        // When
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        static::assertSame($savesBefore + 3, $this->repository->saves);
    }

    #[Test]
    public function aRotationAnnouncesWhichKeyIsRetiring(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        $event = $this->events->of(SigningKeyRotated::class)[1];
        static::assertSame($first, $event->retiring);
        static::assertSame($this->tenant, $event->tenant);
        static::assertSame($this->context, $event->context);
        static::assertSame([], $this->events->of(SigningKeyRetired::class));
    }

    #[Test]
    public function theNewKeySignsAtOnce(): void
    {
        // Given
        $this->firstRotation();
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $provider = new SealedKeyProvider($this->repository, Keys::sealer());

        // When
        $active = $provider->activeKey($this->tenant, SignatureAlgorithm::RS256);

        // Then
        static::assertSame(Keys::otherPair()->privateJwk, $active->privateJwk);
    }

    /**
     * The compromise path: no window, the previous key is out of the JWK Set at once.
     */
    #[Test]
    public function aRotationForACompromiseRetiresThePreviousKeyAtOnce(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context, compromised: true);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertEquals($this->clock->now(), $first->retiringAt);
        static::assertEquals($this->clock->now(), $first->retirementDueAt);
        static::assertEquals($this->clock->now(), $first->retiredAt);
        static::assertSame([$second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function aRotationForACompromiseSaysSo(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context, compromised: true);

        // Then
        [$event] = $this->events->of(SigningKeyRetired::class);
        static::assertSame($first, $event->retired);
        static::assertSame(RetirementReason::Compromised, $event->reason);
        static::assertSame($this->context, $event->context);
        static::assertSame($first, $this->events->of(SigningKeyRotated::class)[1]->retiring);
    }

    #[Test]
    public function aRotationForACompromiseWithoutAnActiveKeyActivatesAKey(): void
    {
        // When
        $key = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context, compromised: true);

        // Then
        static::assertTrue($key->isActive());
        static::assertSame([], $this->events->of(SigningKeyRetired::class));
    }

    /**
     * The timed step: a key past its retirement date is retired, and not before.
     */
    #[Test]
    public function retireDueRetiresAKeyPastItsRetirementDate(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+1 hour');
        $savesBefore = $this->repository->saves;

        // When
        $retired = $this->rotator->retireDue($this->tenant, $this->context);

        // Then
        static::assertSame([$first], $retired);
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertEquals($this->clock->now(), $first->retiredAt);
        static::assertSame($savesBefore + 1, $this->repository->saves);
        static::assertSame([$second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function retireDueLeavesAKeyInsideItsRetirementWindow(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+59 minutes 59 seconds');
        $savesBefore = $this->repository->saves;

        // When
        $retired = $this->rotator->retireDue($this->tenant, $this->context);

        // Then
        static::assertSame([], $retired);
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame($savesBefore, $this->repository->saves);
        static::assertSame([$first, $second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function retireDueSaysTimeDidIt(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+1 day');

        // When
        $this->rotator->retireDue($this->tenant, $this->context);

        // Then
        [$event] = $this->events->of(SigningKeyRetired::class);
        static::assertSame($first, $event->retired);
        static::assertSame(RetirementReason::Due, $event->reason);
        static::assertSame($this->tenant, $event->tenant);
        static::assertSame($this->context, $event->context);
    }

    #[Test]
    public function aDueKeyIsRetiredByHandAsDue(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+1 day');

        // When
        $this->rotator->retire($this->tenant, $first->kid, $this->context);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertSame(RetirementReason::Due, $this->events->of(SigningKeyRetired::class)[0]->reason);
        static::assertSame([$second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function aKeyInsideItsRetirementWindowIsNotRetiredWithoutForce(): void
    {
        // Given
        $first = $this->firstRotation();
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+1 minute');

        // Then
        $this->expectException(RetirementNotDueException::class);
        $this->expectExceptionMessageIs(sprintf('The key "%s" is not due for retirement before 2026-10-15T15:00:00+00:00: a JWS it signed may be alive.', $first->kid));

        // When
        $this->rotator->retire($this->tenant, $first->kid, $this->context);
    }

    #[Test]
    public function aKeyInsideItsRetirementWindowStaysPublishedAfterTheRefusal(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // When
        try {
            $this->rotator->retire($this->tenant, $first->kid, $this->context);
        } catch (RetirementNotDueException) {
        }

        // Then
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertSame([$first, $second], $this->repository->findPublished($this->tenant));
        static::assertSame([], $this->events->of(SigningKeyRetired::class));
    }

    #[Test]
    public function forcingRetiresAKeyInsideItsRetirementWindowAsForced(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+1 minute');

        // When
        $this->rotator->retire($this->tenant, $first->kid, $this->context, force: true);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertEquals($this->clock->now(), $first->retiredAt);
        static::assertSame(RetirementReason::Forced, $this->events->of(SigningKeyRetired::class)[0]->reason);
        static::assertSame([$second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function theActiveKeyCannotBeRetiredWithoutARotation(): void
    {
        // Given
        $key = $this->firstRotation();

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The active key cannot be retired; rotate first.');

        // When
        $this->rotator->retire($this->tenant, $key->kid, $this->context, force: true);
    }

    #[Test]
    public function aStagedKeyCannotBeRetired(): void
    {
        // Given
        $staged = $this->rotator->stage($this->tenant, SignatureAlgorithm::RS256, $this->context);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Only a retiring key can be retired; this one is staged.');

        // When
        $this->rotator->retire($this->tenant, $staged->kid, $this->context, force: true);
    }

    #[Test]
    public function retiringAnUnknownKeyFails(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->rotator->retire($this->tenant, 'nope', $this->context);
    }

    private function firstRotation(): SigningKey
    {
        $key = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, $this->context);
        $this->clock->modify('+30 days');

        return $key;
    }

    /**
     * @param list<IssuedJwsKindInterface> $issuedJws
     */
    private function rotator(array $issuedJws): SigningKeyRotator
    {
        return new SigningKeyRotator($this->repository, new PrecomputedKeyPairGenerator(Keys::pair(), Keys::otherPair()), Keys::sealer(), $issuedJws, new DateInterval(self::STAGING_DELAY), $this->clock, $this->events);
    }
}

/**
 * Hands out pre-generated pairs: generating RSA keys in every test would cost seconds for nothing.
 */
final class PrecomputedKeyPairGenerator implements KeyPairGeneratorInterface
{
    /**
     * @var list<GeneratedKeyPair>
     */
    private array $pairs;

    public function __construct(GeneratedKeyPair ...$pairs)
    {
        $this->pairs = array_values($pairs);
    }

    public function generate(SignatureAlgorithm $algorithm): GeneratedKeyPair
    {
        return array_shift($this->pairs) ?? throw new LogicException('No more precomputed key pairs.');
    }
}
