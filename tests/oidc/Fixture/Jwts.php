<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function base64_decode;
use DateTimeImmutable;
use function explode;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JoseEncryptionAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryJwsSigner;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Oidc\Application\Client\ClientDocumentIssuer;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJweEncrypter;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use function is_array;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Assert;
use function strtr;
use Symfony\Component\Clock\MockClock;

/**
 * A tenant with one real active RS256 key, signing through the bridge of the core, and the verification a
 * relying party performs with web-token/jwt-library against the published JWK Set. activate() gives the
 * tenant a key of another algorithm, for a client that registered that one.
 */
final readonly class Jwts
{
    public TenantKey $key;

    public SealedKeyProvider $keys;

    public JwtLibraryJwsSigner $signer;

    public JoseSignatureAlgorithms $algorithms;

    /**
     * What mints the three documents a client receives, signed and, for a client that registered one,
     * encrypted to a key it publishes.
     */
    public ClientDocumentIssuer $documents;

    private InMemoryTenantKeyRepository $repository;

    public function __construct(
        public Tenant $tenant,
    ) {
        $this->algorithms = Algorithms::all();
        $this->repository = new InMemoryTenantKeyRepository();
        $this->key = $this->activate(Algorithms::rs256(), Keys::pair());
        $this->keys = new SealedKeyProvider($this->repository, Keys::opened());
        $this->signer = new JwtLibraryJwsSigner($this->keys, $this->algorithms);
        $this->documents = $this->documentsFor();
    }

    /**
     * The document issuer, reading the keys a client publishes through the fetcher given, or through the
     * one every other fixture uses.
     */
    public function documentsFor(?ClientJwksFetcherInterface $fetcher = null): ClientDocumentIssuer
    {
        return new ClientDocumentIssuer(
            $this->signer,
            $this->algorithms,
            Methods::keySetProvider($fetcher),
            new JwtLibraryJweEncrypter(new JoseEncryptionAlgorithms(Algorithms::keyEncryption(), Algorithms::contentEncryption())->manager()),
        );
    }

    /**
     * An active key of that algorithm for the tenant, published in its JWK Set beside the others.
     */
    public function activate(KeyAlgorithmInterface $algorithm, ?GeneratedKeyPair $pair = null): TenantKey
    {
        $pair ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate($algorithm);
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->repository->save($key);

        return $key;
    }

    /**
     * The signature against the JWK Set of the tenant, then "iss", "aud", "exp" and "iat" the way a
     * relying party checks them (OIDC Core §3.1.3.7) at the time given. A logout token has no "exp"
     * (RFC 8417 §2), so what must be there is said by the caller.
     *
     * @param list<string> $mandatory the claims the token must carry
     *
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     */
    public function verify(string $compactJws, string $audience, DateTimeImmutable $at, array $mandatory = ['iss', 'aud', 'exp', 'iat']): array
    {
        $jws = new CompactSerializer()->unserialize($compactJws);
        Assert::assertTrue(
            new JWSVerifier($this->algorithms->manager())->verifyWithKeySet(
                $jws,
                JWKSet::createFromKeyData($this->keys->publicKeys($this->tenant)->toJwks()),
                0,
            ),
            'the signature verifies against the published JWKS',
        );
        $claims = self::decode((string) $jws->getPayload());
        $clock = new MockClock($at);
        new ClaimCheckerManager([
            new IssuerChecker([(string) $this->tenant->issuer]),
            new AudienceChecker($audience),
            new ExpirationTimeChecker($clock),
            new IssuedAtChecker($clock),
        ])->check($claims, $mandatory);

        return [
            'header' => $jws->getSignature(0)->getProtectedHeader(),
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
