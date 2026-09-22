<?php

declare(strict_types=1);

/*
 * The DPoP side of "castor demo --dpop" (.castor/lab/demo.php, demo_dpop_check): a client that holds a key
 * pair, exchanges an authorization code for an access token bound to it (RFC 9449 §5), and presents that
 * token to the resource server of oidc-demo, once as its holder and then as someone who took it off the
 * wire would. The task is what runs under castor, which loads no code of the monorepo; this script runs
 * under the autoloader of the monorepo, in one process, so that the key that asked for the token is the
 * key that proves it.
 *
 * Reads one JSON object on stdin: "token_endpoint", "cafile" (the CA of the OP), "client_id",
 * "client_secret", "redirect_uri", "code" and "code_verifier" (the authorization the task walked the
 * browser through), and "api_url" (the route of the demonstration this token is presented to). Writes one
 * JSON object on stdout: what the token response said of the token, and the status and the challenge of
 * each of the five ways it was then presented.
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
 * A client that binds its access token to a key it holds (RFC 9449): one key pair, one proof per request,
 * and every proof signed with the key the token was bound to, except where the run asks for another one.
 */
final readonly class DpopClient
{
    /**
     * RFC 9449 §4.2: what tells a proof from every other JWT a client signs, and §5, the token type a
     * bound token is issued and presented under.
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
        // the demonstration serves a certificate of the Symfony CLI, verified against nothing, as the task
        // does for it
        $this->resourceServer = HttpClient::create([
            'max_redirects' => 0,
            'verify_peer' => false,
            'verify_host' => false,
        ]);
        $this->jws = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $this->serializer = new CompactSerializer();
    }

    /**
     * RFC 9449 §5: the token request carries a proof made for the token endpoint, and the provider binds
     * what it issues to the key of that proof.
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
     * One call of the resource server, as the holder of the key or as whoever holds the token alone.
     *
     * @param JWK|null $proofKey what signs a proof made for this call: the key of the token or another key
     * @param string|null $proof a proof already made, which is how the same one is presented twice
     *
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
     * RFC 9449 §4.2: a proof is a JWT carrying the public key it is signed with, and naming the request it
     * was made for; §7.1 adds the hash of the access token the request presents.
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

// the proof the holder of the key makes for this call, and the key someone who took the token off the
// wire would sign their own with
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
            // the holder of the key, with the proof made for this request
            'held' => $call($client->call($url, $accessToken, 'DPoP', null, $proof)),
            // the same proof again, which nobody may use twice (§11.1)
            'replayed' => $call($client->call($url, $accessToken, 'DPoP', null, $proof)),
            // whoever took the token off the wire: with a key of their own, with no proof at all, or as a bearer
            'foreign_key' => $call($client->call($url, $accessToken, 'DPoP', $foreignKey)),
            'no_proof' => $call($client->call($url, $accessToken)),
            'as_bearer' => $call($client->call($url, $accessToken, 'Bearer')),
        ],
        \JSON_THROW_ON_ERROR,
    )
        . "\n",
);
