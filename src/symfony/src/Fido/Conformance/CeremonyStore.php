<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Fido\Conformance;

use function hash;
use function is_array;
use function is_string;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * The options of a ceremony of the conformance tools between the two requests it takes, found back by
 * the challenge the response carries (WebAuthn Level 3 §7.1 step 8, §7.2 step 12): the tools hold no
 * cookie, a challenge is 32 random bytes and is answered at most once (§13.4.3). Kept in the cache of the
 * application for the time a ceremony may take.
 */
final readonly class CeremonyStore
{
    /**
     * WebAuthn Level 3 §5.4, "timeout": what a ceremony of the tools may take, generous.
     */
    public const int LIFETIME = 300;

    public function __construct(
        private CacheItemPoolInterface $cache,
    ) {
    }

    public function storeCreation(Uuid $userId, PublicKeyCredentialCreationOptions $options): void
    {
        $item = $this->cache->getItem(self::key('creation', $options->challenge));
        $item->set([
            'user' => $userId->toRfc4122(),
            'options' => $options,
        ]);
        $item->expiresAfter(self::LIFETIME);
        $this->cache->save($item);
    }

    /**
     * The creation options drawn with this challenge and the user they were drawn for, once.
     *
     * @return array{Uuid, PublicKeyCredentialCreationOptions}|null
     */
    public function takeCreation(string $challenge): ?array
    {
        $key = self::key('creation', $challenge);
        $stored = $this->cache->getItem($key)->get();
        $this->cache->deleteItem($key);
        if (! is_array($stored) || ! is_string($stored['user'] ?? null) || ! ($stored['options'] ?? null) instanceof PublicKeyCredentialCreationOptions) {
            return null;
        }

        return [Uuid::fromString($stored['user']), $stored['options']];
    }

    public function storeRequest(PublicKeyCredentialRequestOptions $options): void
    {
        $item = $this->cache->getItem(self::key('request', $options->challenge));
        $item->set($options);
        $item->expiresAfter(self::LIFETIME);
        $this->cache->save($item);
    }

    public function takeRequest(string $challenge): ?PublicKeyCredentialRequestOptions
    {
        $key = self::key('request', $challenge);
        $options = $this->cache->getItem($key)->get();
        $this->cache->deleteItem($key);

        return $options instanceof PublicKeyCredentialRequestOptions ? $options : null;
    }

    private static function key(string $ceremony, string $challenge): string
    {
        return 'beffroi.fido.conformance.' . $ceremony . '.' . hash('sha256', $challenge);
    }
}
