<?php

declare(strict_types=1);

/*
 * The client side of "castor demo --attested" (.castor/lab/demo.php, demo_attested_check): a client whose
 * registration this provider authorises on nothing it issued, and everything on a statement an authority the
 * tenant pinned signed (RFC 7591 §2.3, the fourth mode of decision 0009).
 *
 * It is the mode that crosses the boundary of an organisation: an initial access token is a secret this
 * provider issues, counts and revokes for every team that integrates, where a statement is signed by whoever
 * distributes the software and read by whoever pinned that authority. Nothing of this provider is presented
 * here, and the only credential the client ends up with is the one the 201 hands it.
 *
 * The task is what runs under castor, which loads no code of the monorepo; this script runs under the
 * autoloader of the monorepo, for its HTTP client and for the one thing a task cannot do, sign. It plays one
 * pass: the statement that registers, then the four refusals, each one a rule and not an accident. The
 * browser and the token belong to the walk, which has both already.
 *
 * Reads one JSON object on stdin and writes one JSON object on stdout.
 */

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

require __DIR__ . '/../../vendor/autoload.php';

/**
 * An authority that attests a piece of software, as far as this demonstration is concerned: a store, a
 * publisher, the security team of a group. It signs statements about the software and never about a user,
 * which is what tells its key from the one of the trusted issuer of "castor demo --assertion"; the provider
 * holds its public half alone and reads no key a statement carries (RFC 8725 §3.10).
 */
final readonly class AttestationAuthority
{
    private const string ALGORITHM = 'ES256';

    private JWSBuilder $jws;

    private CompactSerializer $serializer;

    public function __construct(
        private JWK $key,
        private string $issuer,
    ) {
        $this->jws = new JWSBuilder(new AlgorithmManager([new ES256()]));
        $this->serializer = new CompactSerializer();
    }

    /**
     * RFC 7591 §2.3: the claims of a statement are client metadata, plus what says whose it is and how long
     * it is good for. This provider requires the last ones of every signed thing it takes back (decision
     * 0006): one audience, its own identifier, an "exp" it bounds, an "iat" and an identifier of its own,
     * which is what makes one statement register one client.
     *
     * @param array<string, mixed> $members what the authority says of the software and of the client
     *
     * @return array{0: string, 1: array<string, mixed>} the compact JWS and the claims it carries
     */
    public function sign(string $audience, array $members, int $lifetime = 60): array
    {
        $now = time();
        $claims = [
            'iss' => $this->issuer,
            'aud' => $audience,
            'iat' => $now,
            'exp' => $now + $lifetime,
            // drawn, never counted: an identifier a replay guard remembers must not be one another party
            // can produce
            'jti' => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='),
            ...$members,
        ];
        $jws = $this->jws
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($this->key, [
                'alg' => self::ALGORITHM,
                'kid' => $this->key->get('kid'),
                'typ' => 'JWT',
            ])
            ->build();

        return [$this->serializer->serialize($jws, 0), $claims];
    }
}

/**
 * The client the statement is about. It writes the registration of RFC 7591 §3.1 like any other client, and
 * the one thing that tells it apart is what authorises it: the statement in the body, under the member
 * RFC 7591 §2 gives it, and no credential of this provider in any header.
 */
final readonly class AttestedClient
{
    private HttpClientInterface $http;

    public function __construct(
        string $cafile,
        private string $endpoint,
    ) {
        $this->http = HttpClient::create([
            'max_redirects' => 0,
            'cafile' => $cafile,
        ]);
    }

    /**
     * @param array<string, mixed> $metadata what the client says of itself
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public function register(array $metadata, ?string $statement): array
    {
        if ($statement !== null) {
            $metadata['software_statement'] = $statement;
        }

        try {
            $response = $this->http->request('POST', $this->endpoint, [
                'headers' => ['Content-Type' => 'application/json'],
                'body' => json_encode($metadata, JSON_THROW_ON_ERROR),
            ]);
            $status = $response->getStatusCode();
            $body = json_decode($response->getContent(false), true, 8, JSON_THROW_ON_ERROR);
        } catch (HttpExceptionInterface $exception) {
            return [
                'status' => 0,
                'body' => ['error' => $exception->getMessage()],
            ];
        }

        return [
            'status' => $status,
            'body' => is_array($body) ? attestation_cli_named($body) : [],
        ];
    }
}

/**
 * @param array<array-key, mixed> $decoded
 *
 * @return array<string, mixed>
 */
function attestation_cli_named(array $decoded): array
{
    $named = [];
    foreach ($decoded as $name => $value) {
        $named[(string) $name] = $value;
    }

    return $named;
}

/**
 * @param array<string, mixed> $input
 */
function attestation_cli_text(array $input, string $name): string
{
    $value = $input[$name] ?? null;

    return is_string($value) && $value !== '' ? $value : throw new RuntimeException(sprintf('The input carries no "%s".', $name));
}

/**
 * @param array<string, mixed> $input
 *
 * @return array<string, mixed>
 */
function attestation_cli_object(array $input, string $name): array
{
    $value = $input[$name] ?? null;

    return is_array($value) ? attestation_cli_named($value) : throw new RuntimeException(sprintf('The input carries no "%s" object.', $name));
}

/**
 * The first key of a set held whole, private half included: what an authority signs with.
 */
function attestation_cli_key(string $file): JWK
{
    $set = json_decode((string) file_get_contents($file), true, 8, JSON_THROW_ON_ERROR);
    $keys = is_array($set) && is_array($set['keys'] ?? null) ? $set['keys'] : [];

    return is_array($keys[0] ?? null) ? new JWK($keys[0]) : throw new RuntimeException(sprintf('%s carries no key.', $file));
}

$read = json_decode((string) file_get_contents('php://stdin'), true, 16, JSON_THROW_ON_ERROR);
if (! is_array($read)) {
    throw new RuntimeException('This program reads one JSON object on its standard input.');
}
$input = attestation_cli_named($read);
$audience = attestation_cli_text($input, 'audience');
$authority = new AttestationAuthority(
    attestation_cli_key(attestation_cli_text($input, 'jwks_file')),
    attestation_cli_text($input, 'authority'),
);
// An authority this tenant pinned for something else: it signs the assertions of "castor demo --assertion",
// and a tenant that trusts it about a user has not pinned it about a piece of software (RFC 7591 §2.3).
$stranger = new AttestationAuthority(
    attestation_cli_key(attestation_cli_text($input, 'stranger_jwks_file')),
    attestation_cli_text($input, 'stranger_authority'),
);
$client = new AttestedClient(attestation_cli_text($input, 'cafile'), attestation_cli_text($input, 'registration_endpoint'));
$metadata = attestation_cli_object($input, 'metadata');
$attested = attestation_cli_object($input, 'attested');

// The one that registers, then the four refusals: the same statement again (one statement registers one
// client), one signed by an authority this tenant did not pin for statements, one an authority signed for
// somebody else, and a body carrying none at all, which is a request presenting nothing this mode acts on.
[$statement, $claims] = $authority->sign($audience, $attested);
$registered = $client->register($metadata, $statement);
$replayed = $client->register($metadata, $statement);
[$signedByAStranger] = $stranger->sign($audience, $attested);
[$addressedElsewhere] = $authority->sign(attestation_cli_text($input, 'elsewhere'), $attested);

fwrite(STDOUT, json_encode(
    [
        'statement' => $claims,
        'registered' => $registered,
        'replayed' => $replayed,
        'stranger' => $client->register($metadata, $signedByAStranger),
        'elsewhere' => $client->register($metadata, $addressedElsewhere),
        'without_statement' => $client->register($metadata, null),
    ],
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
)
    . "\n");
