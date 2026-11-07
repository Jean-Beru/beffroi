<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * The keys of one tenant in the states a test names, behind a provider whose sealer counts what it opens.
 */
final readonly class HeldKeys
{
    public InMemoryTenantKeyRepository $repository;

    public CountingKeySealer $sealer;

    public SealedKeyProvider $provider;

    public function __construct(
        public Tenant $tenant,
    ) {
        $this->repository = new InMemoryTenantKeyRepository();
        $this->sealer = new CountingKeySealer();
        $this->provider = new SealedKeyProvider($this->repository, new OpenedKeys($this->sealer));
    }

    public function staged(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = $this->key($algorithm, $pair);
        $this->repository->save($key);

        return $key;
    }

    public function active(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = $this->key($algorithm, $pair);
        $key->activate(Fixtures::now());
        $this->repository->save($key);

        return $key;
    }

    public function retired(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = $this->key($algorithm, $pair);
        $key->activate(Fixtures::now());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->repository->save($key);

        return $key;
    }

    private function key(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        return new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            [
                ...$pair->publicJwk,
                'alg' => $algorithm->name(),
                'use' => $algorithm->keyUse()->value,
            ],
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
    }
}
