<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Application\Journal\ChainWalk;
use Beffroi\Core\Application\Journal\JournalCheckpoints;
use Beffroi\Core\Application\Journal\JournalCut;
use Beffroi\Core\Application\Journal\JournalRetention;
use Beffroi\Core\Application\Journal\JournalSignature;
use Beffroi\Core\Application\Journal\JournalVerification;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsVerifier;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Listing\RetentionWindow;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Clock\MockClock;

/**
 * The journal of one tenant, its signatures kept apart, signed under a key of that tenant as the provider signs it.
 */
final readonly class SignedJournal
{
    public const int RETENTION = 180;

    public Tenant $tenant;

    public ChainOfWrittenActs $chain;

    public KeptCheckpoints $kept;

    public JournalCheckpoints $checkpoints;

    public MockClock $clock;

    private InMemoryTenantKeyRepository $keys;

    private ChainWalk $walk;

    public function __construct()
    {
        $this->tenant = Fixtures::tenant();
        $this->chain = new ChainOfWrittenActs();
        $this->kept = new KeptCheckpoints();
        $this->clock = new MockClock(Fixtures::now());
        $this->keys = new InMemoryTenantKeyRepository();
        $this->activate(Keys::pair());
        $provider = new SealedKeyProvider($this->keys, Keys::opened());
        $this->checkpoints = new JournalCheckpoints(
            $this->kept,
            new JwtLibraryJwsSigner($provider, Algorithms::all()),
            new JwtLibraryJwsVerifier($provider, Algorithms::all()),
            Algorithms::all(),
        );
        $this->walk = new ChainWalk($this->chain);
    }

    public function signature(): JournalSignature
    {
        return new JournalSignature($this->chain, $this->walk, $this->checkpoints, new WritesAsTheyCome(), $this->clock);
    }

    public function cut(): JournalCut
    {
        return new JournalCut(
            $this->chain,
            $this->chain,
            $this->walk,
            $this->checkpoints,
            new WritesAsTheyCome(),
            $this->clock,
            new JournalRetention($this->clock, new RetentionWindow(self::RETENTION)),
        );
    }

    public function verification(): JournalVerification
    {
        return new JournalVerification($this->chain, $this->walk, $this->checkpoints);
    }

    /**
     * The key that signed so far leaves the JWK Set: retired as if its window had passed.
     */
    public function retireTheKeyThatSigned(): void
    {
        foreach ($this->keys->findAll($this->tenant) as $key) {
            if ($key->isActive()) {
                $key->startRetiring(Fixtures::now(), Fixtures::now());
                $key->retire(Fixtures::now());
                $this->keys->save($key);
            }
        }
        $this->activate(Keys::otherPair());
    }

    private function activate(GeneratedKeyPair $pair): void
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            Algorithms::rs256(),
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);
    }
}
