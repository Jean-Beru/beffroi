<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 7517 §5 and architecture §4.8: the published keys, cacheable once there is one, never while there
 * is none.
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

    #[Test]
    public function thePublishedKeysAreCacheableForFiveMinutes(): void
    {
        // Given
        self::signingKey();

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        $response = $this->browser->getResponse();
        static::assertTrue($response->headers->hasCacheControlDirective('public'));
        static::assertSame('300', $response->headers->getCacheControlDirective('max-age'));
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
}
