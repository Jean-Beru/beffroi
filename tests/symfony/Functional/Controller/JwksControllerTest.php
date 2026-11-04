<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 7517 §5, OIDC Core §10.1.1, Architecture §4.8, §3.3
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
        static::assertSame(
            [
                'keys' => [],
            ],
            self::json($response),
        );
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
     * Architecture §3.3
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
     * OIDC Core §10.1.1
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
     * OIDC Core §10.1.1
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
     * RFC 7517 §4.2, §4.4, §4.5
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
     * Architecture §3.3
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
     * @return list<string> in the order served
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
