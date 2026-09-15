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
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\KeyPairGeneratorInterface;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class SigningKeyRotatorTest extends TestCase
{
    /**
     * Spike 2 criterion, prepared here: the new key signs at once, the old one stays published, the tokens it
     * signed remain verifiable, then it leaves the JWK Set when retired.
     */
    #[Test]
    public function rotationActivatesTheNewKeyAndKeepsThePreviousOnePublished(): void
    {
        $tenant = Fixtures::tenant();
        $repository = new InMemorySigningKeyRepository();
        $events = new RecordingEventDispatcher();
        $clock = new MockClock('2026-09-15T14:00:00+00:00');
        $rotator = new SigningKeyRotator($repository, new PrecomputedKeyPairGenerator(Keys::pair(), Keys::otherPair()), Keys::sealer(), $clock, $events);
        $context = RequestContext::unknown($clock->now());

        $first = $rotator->rotate($tenant, SignatureAlgorithm::RS256, $context);
        static::assertSame(Keys::pair()->kid, $first->kid);
        static::assertTrue($first->isActive());
        static::assertSame($first, $repository->findActive($tenant, SignatureAlgorithm::RS256));
        static::assertNull($events->of(SigningKeyRotated::class)[0]->retiring);

        $clock->modify('+30 days');
        $savesBefore = $repository->saves;
        $second = $rotator->rotate($tenant, SignatureAlgorithm::RS256, RequestContext::unknown($clock->now()));
        static::assertSame($savesBefore + 2, $repository->saves);
        static::assertSame($second, $repository->findActive($tenant, SignatureAlgorithm::RS256));
        static::assertSame(KeyStatus::Retiring, $first->status);
        static::assertEquals($clock->now(), $first->retiringAt);
        static::assertSame([$first, $second], $repository->findPublished($tenant));
        static::assertSame($first, $events->of(SigningKeyRotated::class)[1]->retiring);
        static::assertSame($tenant, $events->of(SigningKeyRotated::class)[1]->tenant);

        $provider = new SealedKeyProvider($repository, Keys::sealer());
        static::assertSame(Keys::otherPair()->privateJwk, $provider->activeKey($tenant, SignatureAlgorithm::RS256)->privateJwk);

        $clock->modify('+1 day');
        $savesBefore = $repository->saves;
        $rotator->retire($tenant, $first->kid);
        static::assertSame($savesBefore + 1, $repository->saves);
        static::assertSame(KeyStatus::Retired, $first->status);
        static::assertSame([$second], $repository->findPublished($tenant));
    }

    #[Test]
    public function theActiveKeyCannotBeRetiredWithoutARotation(): void
    {
        $tenant = Fixtures::tenant();
        $rotator = new SigningKeyRotator(new InMemorySigningKeyRepository(), new PrecomputedKeyPairGenerator(Keys::pair()), Keys::sealer(), new MockClock(), new RecordingEventDispatcher());
        $key = $rotator->rotate($tenant, SignatureAlgorithm::RS256, RequestContext::unknown(Fixtures::now()));

        $this->expectException(LogicException::class);
        $rotator->retire($tenant, $key->kid);
    }

    #[Test]
    public function retiringAnUnknownKeyFails(): void
    {
        $rotator = new SigningKeyRotator(new InMemorySigningKeyRepository(), new PrecomputedKeyPairGenerator(), Keys::sealer(), new MockClock(), new RecordingEventDispatcher());

        $this->expectException(KeyNotFoundException::class);
        $rotator->retire(Fixtures::tenant(), 'nope');
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
