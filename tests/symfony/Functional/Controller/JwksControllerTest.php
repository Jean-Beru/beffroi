<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 7517 §5 and architecture §4.8: the published keys, cacheable once there is one, never while there
 * is none; across a rotation (OIDC Core §10.1.1, architecture §3.3), the set a relying party sees.
 */
final class JwksControllerTest extends BrowserTestCase
{
    #[Test]
    public function anEmptySetIsServedAsJson(): void
    {
        // When
        $this->browser->request('GET', '/jwks');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertSame([
            'keys' => [],
        ], self::json($response));
    }

    #[Test]
    public function anEmptySetIsNotCached(): void
    {
        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertTrue($this->browser->getResponse()->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * The lifetime is the one configured, "heidi.keys.jwks_max_age", two minutes in this kernel: the same
     * value the staging window of a rotation derives from (architecture §3.3).
     */
    #[Test]
    public function thePublishedKeysAreCacheableForTheConfiguredTime(): void
    {
        // Given
        self::signingKey();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        $response = $this->browser->getResponse();
        static::assertTrue($response->headers->hasCacheControlDirective('public'));
        static::assertSame('120', $response->headers->getCacheControlDirective('max-age'));
    }

    #[Test]
    public function thePublishedKeysAreServedWithoutAnyPrivateMember(): void
    {
        // Given
        self::signingKey();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        $keys = self::json($response)['keys'];
        static::assertIsArray($keys);
        static::assertCount(1, $keys);
        $key = $keys[0];
        static::assertIsArray($key);
        static::assertSame('RSA', $key['kty']);
        static::assertSame('sig', $key['use']);
        static::assertSame('RS256', $key['alg']);
        static::assertArrayHasKey('kid', $key);
        static::assertArrayNotHasKey('d', $key);
        static::assertArrayNotHasKey('p', $key);
    }

    /**
     * OIDC Core §10.1.1: during the retirement window, the key that signed and the one that signs are
     * both served, in creation order.
     */
    #[Test]
    public function aRotationPublishesTheRetiringAndTheActiveKeyInCreationOrder(): void
    {
        // Given
        $previous = self::signingKey();
        $active = self::signingKey();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame([$previous->kid, $active->kid], self::publishedKids());
    }

    /**
     * §10.1.1: the new key is published before it signs, after the ones that came before it.
     */
    #[Test]
    public function aStagedKeyIsPublishedBeforeItSigns(): void
    {
        // Given
        $active = self::signingKey();
        $staged = self::stagedKey();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame([$active->kid, $staged->kid], self::publishedKids());
    }

    /**
     * Every key of the set says what it is for and with what (RFC 7517 §4.2, §4.4, §4.5), whatever its
     * place in the lifecycle.
     */
    #[Test]
    public function everyPublishedKeyCarriesItsKidUseAndAlg(): void
    {
        // Given
        self::signingKey();
        self::signingKey();
        self::stagedKey();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        $keys = self::json($this->browser->getResponse())['keys'];
        static::assertIsArray($keys);
        static::assertCount(3, $keys);
        foreach ($keys as $key) {
            static::assertIsArray($key);
            static::assertNotSame('', $key['kid'] ?? '');
            static::assertSame('sig', $key['use']);
            static::assertSame('RS256', $key['alg']);
        }
    }

    /**
     * A retired key leaves the set: a token naming it is refused from then on (architecture §3.3).
     */
    #[Test]
    public function aRetiredKeyLeavesTheSet(): void
    {
        // Given
        $previous = self::signingKey();
        $active = self::signingKey();
        self::retireKey($previous);

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame([$active->kid], self::publishedKids());
    }

    /**
     * @return list<string> the "kid" of every key served, in the order served
     */
    private function publishedKids(): array
    {
        $keys = self::json($this->browser->getResponse())['keys'];
        static::assertIsArray($keys);
        $kids = [];
        foreach ($keys as $key) {
            static::assertIsArray($key);
            $kids[] = self::string($key['kid'] ?? null);
        }

        return $kids;
    }
}
