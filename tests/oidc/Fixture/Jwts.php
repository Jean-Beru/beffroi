<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function base64_decode;
use DateTimeImmutable;
use function explode;
use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Bridge\JwtFramework\JwtFrameworkJwsSigner;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use function is_array;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Assert;
use function strtr;
use Symfony\Component\Clock\MockClock;

/**
 * A tenant with one real active RSA key, signing through the bridge of the core, and the verification a
 * relying party performs with web-token/jwt-library against the published JWK Set.
 */
final readonly class Jwts
{
    public SigningKey $key;

    public SealedKeyProvider $keys;

    public JwtFrameworkJwsSigner $signer;

    public function __construct(
        public Tenant $tenant,
    ) {
        $repository = new InMemorySigningKeyRepository();
        $this->key = new SigningKey(Keys::pair()->kid, $tenant, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, Keys::sealer()->seal(Keys::pair()->privateJwk), Fixtures::now());
        $repository->save($this->key);
        $this->keys = new SealedKeyProvider($repository, Keys::sealer());
        $this->signer = new JwtFrameworkJwsSigner($this->keys);
    }

    /**
     * The signature against the JWK Set of the tenant, then "iss", "aud", "exp" and "iat" the way a
     * relying party checks them (OIDC Core §3.1.3.7) at the time given.
     *
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     */
    public function verify(string $compactJws, string $audience, DateTimeImmutable $at): array
    {
        $jws = new CompactSerializer()
            ->unserialize($compactJws);
        Assert::assertTrue(new JWSVerifier(new AlgorithmManager([new RS256()]))->verifyWithKeySet($jws, JWKSet::createFromKeyData($this->keys->publicKeys($this->tenant)->toJwks()), 0), 'the signature verifies against the published JWKS');
        $claims = self::decode((string) $jws->getPayload());
        $clock = new MockClock($at);
        new ClaimCheckerManager([
            new IssuerChecker([(string) $this->tenant->issuer]),
            new AudienceChecker($audience),
            new ExpirationTimeChecker($clock),
            new IssuedAtChecker($clock),
        ])->check($claims, ['iss', 'aud', 'exp', 'iat']);

        return [
            'header' => $jws->getSignature(0)
                ->getProtectedHeader(),
            'claims' => $claims,
        ];
    }

    /**
     * The payload as the wire carries it, before any decoding: what a JSON boolean or number looks like.
     */
    public static function rawPayload(string $compactJws): string
    {
        [, $payload] = explode('.', $compactJws);

        return (string) base64_decode(strtr($payload, '-_', '+/'), true);
    }

    /**
     * @return array<string, mixed>
     */
    public static function decode(string $payload): array
    {
        $claims = json_decode($payload, true, 8, JSON_THROW_ON_ERROR);
        Assert::assertTrue(is_array($claims), 'the payload is a JSON object');

        /** @var array<string, mixed> $claims */
        return $claims;
    }
}
