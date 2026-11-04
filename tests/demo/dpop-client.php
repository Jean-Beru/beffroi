<?php

declare(strict_types=1);

/*
 * The client of "castor demo --dpop": an access token bound to its key (RFC 9449 §5) and presented five ways.
 */

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * RFC 9449
 */
final readonly class DpopClient
{
    /**
     * RFC 9449 §4.2
     */
    private const string PROOF_TYPE = 'dpop+jwt';

    private const string SCHEME = 'DPoP';

    private const string ALGORITHM = 'ES256';

    private HttpClientInterface $provider;

    private HttpClientInterface $resourceServer;

    private JWSBuilder $jws;

    private CompactSerializer $serializer;

    public function __construct(
        string $cafile,
        private JWK $key,
    ) {
        $this->provider = HttpClient::create([
            'max_redirects' => 0,
            'cafile' => $cafile,
        ]);
        // The demonstration serves a certificate of the Symfony CLI, which the task does not verify either.
        $this->resourceServer = HttpClient::create([
            'max_redirects' => 0,
            'verify_peer' => false,
            'verify_host' => false,
        ]);
        $this->jws = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $this->serializer = new CompactSerializer();
    }

    /**
     * RFC 9449 §5
     *
     * @return array{int, array<string, mixed>} the status and the token response
     */
    public function exchange(string $endpoint, string $clientId, string $secret, string $redirectUri, string $code, string $verifier): array
    {
        $response = $this->provider->request('POST', $endpoint, [
            'auth_basic' => $clientId . ':' . $secret,
            'headers' => [
                'DPoP' => $this->proof('POST', $endpoint),
            ],
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'code_verifier' => $verifier,
            ],
        ]);

        return [$response->getStatusCode(), self::json($response->getContent(false))];
    }

    /**
     * @return array{int, string, array<string, mixed>}
     */
    public function call(string $url, string $accessToken, string $scheme = self::SCHEME, ?JWK $proofKey = null, ?string $proof = null): array
    {
        $headers = [
            'Authorization' => $scheme . ' ' . $accessToken,
        ];
        if ($proof !== null) {
            $headers['DPoP'] = $proof;
        } elseif ($proofKey !== null) {
            $headers['DPoP'] = $this->proof('GET', $url, $accessToken, $proofKey);
        }
        $response = $this->resourceServer->request('GET', $url, [
            'headers' => $headers,
        ]);

        $challenge = $response->getHeaders(false)['www-authenticate'][0] ?? '';

        return [
            $response->getStatusCode(),
            is_string($challenge) ? $challenge : '',
            self::json($response->getContent(false)),
        ];
    }

    /**
     * RFC 9449 §4.2, §7.1
     */
    public function proof(string $method, string $url, ?string $accessToken = null, ?JWK $key = null): string
    {
        $key ??= $this->key;
        $claims = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => $method,
            'htu' => $url,
            'iat' => time(),
        ];
        if ($accessToken !== null) {
            $claims['ath'] = self::base64Url(hash('sha256', $accessToken, true));
        }

        return $this->serializer->serialize(
            $this->jws
                ->create()
                ->withPayload((string) json_encode($claims))
                ->addSignature($key, [
                    'typ' => self::PROOF_TYPE,
                    'alg' => self::ALGORITHM,
                    'jwk' => $key->toPublic()->all(),
                ])
                ->build(),
        );
    }

    public function thumbprint(): string
    {
        return $this->key->toPublic()->thumbprint('sha256');
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /**
     * @return array<string, mixed>
     */
    private static function json(string $body): array
    {
        $values = json_decode($body, true);
        $claims = [];
        foreach (is_array($values) ? $values : [] as $name => $value) {
            $claims[(string) $name] = $value;
        }

        return $claims;
    }
}

/** @var array{token_endpoint?: mixed, cafile?: mixed, client_id?: mixed, client_secret?: mixed, redirect_uri?: mixed, code?: mixed, code_verifier?: mixed, api_url?: mixed} $input */
$input = (array) json_decode((string) stream_get_contents(\STDIN), true, 8, \JSON_THROW_ON_ERROR);
$values = [];
foreach (['token_endpoint', 'cafile', 'client_id', 'client_secret', 'redirect_uri', 'code', 'code_verifier', 'api_url'] as $name) {
    $value = $input[$name] ?? null;
    if (! is_string($value) || $value === '') {
        throw new RuntimeException(sprintf('The input names no %s.', $name));
    }
    $values[$name] = $value;
}

$key = JWKFactory::createECKey('P-256', [
    'alg' => 'ES256',
    'use' => 'sig',
]);
$client = new DpopClient($values['cafile'], $key);

[$status, $token] = $client->exchange(
    $values['token_endpoint'],
    $values['client_id'],
    $values['client_secret'],
    $values['redirect_uri'],
    $values['code'],
    $values['code_verifier'],
);
if ($status !== 200) {
    throw new RuntimeException(sprintf('The token endpoint answered %d: %s', $status, (string) json_encode($token)));
}

$accessToken = $token['access_token'] ?? null;
$tokenType = $token['token_type'] ?? null;
if (! is_string($accessToken) || ! is_string($tokenType)) {
    throw new RuntimeException('The token response carries no access token.');
}

$url = $values['api_url'];
$proof = $client->proof('GET', $url, $accessToken);
$foreignKey = JWKFactory::createECKey('P-256', [
    'alg' => 'ES256',
    'use' => 'sig',
]);

/**
 * @param array{int, string, array<string, mixed>} $answer
 * @return array{status: int, challenge: string, body: array<string, mixed>}
 */
$call = static fn (array $answer): array => [
    'status' => $answer[0],
    'challenge' => $answer[1],
    'body' => $answer[2],
];

fwrite(
    \STDOUT,
    json_encode(
        [
            'token_type' => $tokenType,
            'access_token' => $accessToken,
            'jkt' => $client->thumbprint(),
            'held' => $call($client->call($url, $accessToken, 'DPoP', null, $proof)),
            'replayed' => $call($client->call($url, $accessToken, 'DPoP', null, $proof)),
            'foreign_key' => $call($client->call($url, $accessToken, 'DPoP', $foreignKey)),
            'no_proof' => $call($client->call($url, $accessToken)),
            'as_bearer' => $call($client->call($url, $accessToken, 'Bearer')),
        ],
        \JSON_THROW_ON_ERROR,
    )
        . "\n",
);
