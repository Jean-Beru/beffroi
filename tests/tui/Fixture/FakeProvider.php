<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Profile\Profile;
use Beffroi\Tui\Provider\ProviderMetadata;
use function array_filter;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * A provider as this program sees it from the outside: its metadata, its JWK Set and the ID tokens it signs,
 * under a key of its own that the tests can also replace by a key it does not publish.
 */
final readonly class FakeProvider
{
    public const string ISSUER = 'https://op.example';

    public const string CLIENT_ID = 'tui-client';

    public const string ADMINISTRATION = 'https://admin.op.example';

    public const string REDIRECT_URI = 'http://127.0.0.1:0/callback';

    public const string KEY_ID = 'provider-key';

    public const int NOW = 1_800_000_000;

    public JWK $key;

    public function __construct()
    {
        $this->key = JWKFactory::createECKey('P-256', [
            'kid' => self::KEY_ID,
            'alg' => 'ES256',
            'use' => 'sig',
        ]);
    }

    /**
     * The document of OpenID Connect Discovery 1.0 §3 of a provider that announces everything an administrator's
     * sign-in needs, the members given replacing those of the same name.
     *
     * @param array<string, mixed> $replacing
     *
     * @return array<string, mixed>
     */
    public static function metadataDocument(array $replacing = []): array
    {
        return [
            ...[
                'issuer' => self::ISSUER,
                'authorization_endpoint' => self::ISSUER . '/authorize',
                'pushed_authorization_request_endpoint' => self::ISSUER . '/par',
                'token_endpoint' => self::ISSUER . '/token',
                'jwks_uri' => self::ISSUER . '/jwks',
                'userinfo_endpoint' => self::ISSUER . '/userinfo',
                'revocation_endpoint' => self::ISSUER . '/revoke',
                'registration_endpoint' => self::ISSUER . '/register',
                'authorization_response_iss_parameter_supported' => true,
                'code_challenge_methods_supported' => ['S256'],
                'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'private_key_jwt'],
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256', 'ES256'],
                'dpop_signing_alg_values_supported' => ['RS256', 'ES256'],
                'acr_values_supported' => ['phrh', 'phr', '1'],
                'id_token_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256'],
            ],
            ...$replacing,
        ];
    }

    public static function metadata(): ProviderMetadata
    {
        return new ProviderMetadata(
            self::ISSUER,
            self::ISSUER . '/authorize',
            self::ISSUER . '/par',
            self::ISSUER . '/token',
            self::ISSUER . '/jwks',
            ['ES256', 'PS256'],
            self::ISSUER . '/revoke',
            self::ISSUER . '/register',
        );
    }

    public static function profile(SigningKey $clientKey, string $redirectUri = self::REDIRECT_URI): Profile
    {
        return new Profile(self::ISSUER, self::CLIENT_ID, $redirectUri, $clientKey, 'ES256', self::ADMINISTRATION);
    }

    /**
     * The JWK Set the provider publishes: its signing key, an encryption key nothing verifies with, and the keys
     * given.
     *
     * @param list<JWK> $more
     */
    public function jwks(array $more = []): string
    {
        $keys = [
            $this->key->toPublic()->all(),
            [
                ...JWKFactory::createECKey('P-256')->toPublic()->all(),
                'kid' => 'encryption-key',
                'use' => 'enc',
            ],
        ];
        foreach ($more as $key) {
            $keys[] = $key->toPublic()->all();
        }

        return json_encode(['keys' => $keys], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * The claims of an ID token this provider issues to the client for the nonce given, the claims given
     * replacing those of the same name, and a claim given as null left out.
     *
     * @param array<string, mixed> $replacing
     *
     * @return array<string, mixed>
     */
    public static function claims(string $nonce, array $replacing = []): array
    {
        $claims = [
            ...[
                'iss' => self::ISSUER,
                'sub' => 'administrator',
                'aud' => self::CLIENT_ID,
                'exp' => self::NOW + 300,
                'iat' => self::NOW,
                'auth_time' => self::NOW - 10,
                'nonce' => $nonce,
                'acr' => 'phr',
                'amr' => ['hwk', 'user'],
            ],
            ...$replacing,
        ];

        return array_filter($claims, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * An ID token signed by the key given, the provider's when none is, under ES256 unless the header names PS256.
     *
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header
     */
    public function idToken(array $claims, ?JWK $key = null, array $header = []): string
    {
        $jws = new JWSBuilder(new AlgorithmManager([new ES256(), new PS256()]))
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES))
            ->addSignature($key ?? $this->key, [
                ...[
                    'alg' => 'ES256',
                    'kid' => self::KEY_ID,
                ],
                ...$header,
            ])
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }
}
