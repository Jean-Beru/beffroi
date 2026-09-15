<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Application\Key;

use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Event\SigningKeyRotated;
use Heidi\Core\Domain\Key\GeneratedKeyPair;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\KeyPairGeneratorInterface;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Spike 2 criterion, prepared here: the new key signs at once, the old one stays published, the tokens it
 * signed remain verifiable, then it leaves the JWK Set when retired.
 */
final class SigningKeyRotatorTest extends TestCase
{
    private Tenant $tenant;

    private InMemorySigningKeyRepository $repository;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private SigningKeyRotator $rotator;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->repository = new InMemorySigningKeyRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-09-15T14:00:00+00:00');
        $this->rotator = new SigningKeyRotator($this->repository, new PrecomputedKeyPairGenerator(Keys::pair(), Keys::otherPair()), Keys::sealer(), $this->clock, $this->events);
    }

    #[Test]
    public function theFirstRotationActivatesAKeyAndRetiresNothing(): void
    {
        // When
        $first = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));

        // Then
        static::assertSame(Keys::pair()->kid, $first->kid);
        static::assertTrue($first->isActive());
        static::assertSame($first, $this->repository->findActive($this->tenant, SignatureAlgorithm::RS256));
        static::assertNull($this->events->of(SigningKeyRotated::class)[0]->retiring);
    }

    #[Test]
    public function aRotationActivatesTheNewKey(): void
    {
        // Given
        $this->firstRotation();

        // When
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));

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
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));

        // Then
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertEquals($this->clock->now(), $first->retiringAt);
        static::assertSame([$first, $second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function aRotationSavesBothKeys(): void
    {
        // Given
        $this->firstRotation();
        $savesBefore = $this->repository->saves;

        // When
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));

        // Then
        static::assertSame($savesBefore + 2, $this->repository->saves);
    }

    #[Test]
    public function aRotationAnnouncesWhichKeyIsRetiring(): void
    {
        // Given
        $first = $this->firstRotation();

        // When
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));

        // Then
        $event = $this->events->of(SigningKeyRotated::class)[1];
        static::assertSame($first, $event->retiring);
        static::assertSame($this->tenant, $event->tenant);
    }

    #[Test]
    public function theNewKeySignsAtOnce(): void
    {
        // Given
        $this->firstRotation();
        $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));
        $provider = new SealedKeyProvider($this->repository, Keys::sealer());

        // When
        $active = $provider->activeKey($this->tenant, SignatureAlgorithm::RS256);

        // Then
        static::assertSame(Keys::otherPair()->privateJwk, $active->privateJwk);
    }

    #[Test]
    public function retiringARetiringKeyRemovesItFromThePublishedKeys(): void
    {
        // Given
        $first = $this->firstRotation();
        $second = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));
        $this->clock->modify('+1 day');
        $savesBefore = $this->repository->saves;

        // When
        $this->rotator->retire($this->tenant, $first->kid);

        // Then
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertSame($savesBefore + 1, $this->repository->saves);
        static::assertSame([$second], $this->repository->findPublished($this->tenant));
    }

    #[Test]
    public function theActiveKeyCannotBeRetiredWithoutARotation(): void
    {
        // Given
        $key = $this->firstRotation();

        // Then
        $this->expectException(LogicException::class);

        // When
        $this->rotator->retire($this->tenant, $key->kid);
    }

    #[Test]
    public function retiringAnUnknownKeyFails(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->rotator->retire($this->tenant, 'nope');
    }

    private function firstRotation(): SigningKey
    {
        $key = $this->rotator->rotate($this->tenant, SignatureAlgorithm::RS256, RequestContext::unknown($this->clock->now()));
        $this->clock->modify('+30 days');

        return $key;
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
