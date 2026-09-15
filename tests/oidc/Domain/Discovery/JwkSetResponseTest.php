<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Discovery;

use function array_keys;
use Heidi\Core\Domain\Key\PublicKeySet;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Oidc\Domain\Discovery\JwkSetResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class JwkSetResponseTest extends TestCase
{
    /**
     * RFC 7517 §5: a JSON object with a "keys" list of public JWKs, each with "kid", "kty", "alg", "use"
     * (§4) and no private member; served as JSON, publicly cacheable for a short while.
     */
    #[Test]
    public function itServesThePublishedKeysAsAJwkSet(): void
    {
        $key = new SigningKey(Keys::pair()->kid, Fixtures::tenant(), SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $response = new JwkSetResponse(new PublicKeySet([$key]), 300);

        $document = json_decode($response->toJson(), true, 4, JSON_THROW_ON_ERROR);
        static::assertSame([
            'keys' => [$key->publicJwk],
        ], $document);
        static::assertSame(['keys'], array_keys($document));
        static::assertSame('sig', $document['keys'][0]['use']);
        static::assertSame('RS256', $document['keys'][0]['alg']);
        static::assertSame('RSA', $document['keys'][0]['kty']);
        static::assertSame($key->kid, $document['keys'][0]['kid']);
        static::assertArrayNotHasKey('d', $document['keys'][0]);
        static::assertSame([
            'Cache-Control' => 'public, max-age=300',
        ], $response->headers);
    }

    /**
     * A set without any key is still a JWK Set (RFC 7517 §5.1 "keys" may be empty) but is not cached:
     * the first key generated must be seen at once.
     */
    #[Test]
    public function anEmptySetIsNotCached(): void
    {
        $response = new JwkSetResponse(new PublicKeySet([]), 300);

        static::assertSame('{"keys":[]}', $response->toJson());
        static::assertSame([
            'Cache-Control' => 'no-store',
        ], $response->headers);
    }

    #[Test]
    public function theLifetimeIsANumberOfSeconds(): void
    {
        static::assertSame([
            'Cache-Control' => 'public, max-age=0',
        ], new JwkSetResponse(new PublicKeySet([new SigningKey(Keys::pair()->kid, Fixtures::tenant(), SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now())]), 0)->headers);

        try {
            new JwkSetResponse(new PublicKeySet([]), -1);
            static::fail('A negative lifetime is refused.');
        } catch (InvalidArgumentException $e) {
            static::assertStringContainsString('number of seconds', $e->getMessage());
        }
    }
}
