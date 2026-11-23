<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;

const REQUEST_LIMITS_CA_FILE = 'var/caddy-root.crt';

/**
 * What net/http reads above MaxHeaderBytes over HTTP/1.1, the request line and the headers counted together.
 */
const REQUEST_LIMITS_HTTP1_HEADER_SLACK = 4096;

#[AsTask(
    description: 'Measure the bounds of the size of a request at the edge (issue #1191), as the configuration Caddy runs states them: a request head of exactly the header bound served and one just over it answered 431, a body of exactly the bound of each site served and one byte more answered 413, announced or chunked, PHP never running for a refused one',
)]
function request_limits(
    #[AsOption(description: 'The host of SERVER_NAME, with its port when it is not 443')]
    string $host = 'op.localhost',
    #[AsOption(description: 'The host of the listener that asks for a client certificate; MTLS_SERVER_NAME of compose.yaml')]
    string $mtlsHost = DEV_MTLS_SERVER_NAME,
    #[AsOption(description: 'The host of the administration API; ADMINISTRATION_SERVER_NAME of compose.yaml')]
    string $administrationHost = 'admin.op.localhost',
): void {
    io()->title('The size of a request, bounded at the edge');

    $ca = caddy_ca(getcwd() . '/' . REQUEST_LIMITS_CA_FILE);
    [$headerBound, $bodyBounds] = request_limits_running();
    $sites = [
        $host => '/token',
        $mtlsHost => '/token',
        $administrationHost => '/tenant/mail-signing-keys/smime',
    ];
    $measured = [];

    io()->section(sprintf('The request line and the headers, %d bytes', $headerBound));
    foreach (array_keys($sites) as $site) {
        $served = request_limits_send($site, $ca, '/.well-known/openid-configuration', 'GET', $headerBound);
        request_limits_expect($served['status'] !== 431 && $served['reached_php'], sprintf(
            '%s serves a request head of exactly the bound (got %d)',
            $site,
            $served['status'],
        ));
        $over = $headerBound + REQUEST_LIMITS_HTTP1_HEADER_SLACK + 1;
        $refused = request_limits_send($site, $ca, '/.well-known/openid-configuration', 'GET', $over);
        request_limits_expect($refused['status'] === 431 && ! $refused['reached_php'], sprintf(
            '%s answers 431 to a request head of %d bytes, before PHP (got %d)',
            $site,
            $over,
            $refused['status'],
        ));
        $measured[] = [$site, 'headers', sprintf('%d bytes: %d', $headerBound, $served['status']), sprintf('%d bytes: 431', $over)];
    }

    foreach ($sites as $site => $path) {
        $name = (string) preg_replace('/:\d+$/', '', $site);
        $bound = $bodyBounds[$name] ?? null;
        if ($bound === null) {
            io()->error(sprintf('Caddy runs no site for %s that bounds the body of a request.', $name));
            exit(1);
        }
        io()->section(sprintf('The body on %s, %d bytes', $site, $bound));
        $served = request_limits_send($site, $ca, $path, 'POST', 0, $bound);
        request_limits_expect($served['status'] !== 413 && $served['reached_php'], sprintf(
            'a body of exactly the bound reaches PHP (got %d)',
            $served['status'],
        ));
        foreach ([false, true] as $chunked) {
            $refused = request_limits_send($site, $ca, $path, 'POST', 0, $bound + 1, $chunked);
            request_limits_expect($refused['status'] === 413 && ! $refused['reached_php'], sprintf(
                'a body of one byte more, %s, is answered 413 before PHP (got %d)',
                $chunked ? 'chunked' : 'announced by its Content-Length',
                $refused['status'],
            ));
        }
        $measured[] = [$site, 'body', sprintf('%d bytes: %d', $bound, $served['status']), sprintf('%d bytes: 413, announced or chunked', $bound + 1)];
    }

    io()->table(['Site', 'Bound', 'Served', 'Refused'], $measured);
    io()->success('Every site serves a request up to its bounds and refuses one beyond them before PHP runs.');
}

/**
 * The bound of the headers of the listener, and the bound of the body of each site keyed by its host, read from the
 * administration endpoint of Caddy in the op container.
 *
 * @return array{0: int, 1: array<string, int>}
 */
function request_limits_running(): array
{
    $read = run(
        ['docker', 'compose', 'exec', '-T', 'op', 'curl', '-sf', 'localhost:2019/config/apps/http/servers'],
        context: context()->withQuiet()->withAllowFailure(),
    );
    $servers = json_decode($read->getOutput(), true);
    if (! $read->isSuccessful() || ! is_array($servers)) {
        io()->error('The configuration Caddy runs cannot be read: run "castor start" first.');
        exit(1);
    }
    $headerBound = null;
    $bodyBounds = [];
    foreach ($servers as $server) {
        if (! is_array($server) || ! in_array(':443', (array) ($server['listen'] ?? []), true)) {
            continue;
        }
        $headerBound = is_int($server['max_header_bytes'] ?? null) ? $server['max_header_bytes'] : null;
        foreach ((array) ($server['routes'] ?? []) as $route) {
            $bound = request_limits_body_bound($route);
            foreach ((array) ($route['match'] ?? []) as $match) {
                foreach ((array) ($match['host'] ?? []) as $name) {
                    if ($bound !== null) {
                        $bodyBounds[(string) $name] = $bound;
                    }
                }
            }
        }
    }
    if ($headerBound === null) {
        io()->error('The listener of the sites bounds no header: the "servers" block of the Caddyfile is missing.');
        exit(1);
    }

    return [$headerBound, $bodyBounds];
}

function request_limits_body_bound(mixed $node): ?int
{
    if (! is_array($node)) {
        return null;
    }
    if (($node['handler'] ?? null) === 'request_body' && is_int($node['max_size'] ?? null)) {
        return $node['max_size'];
    }
    foreach ($node as $child) {
        $bound = request_limits_body_bound($child);
        if ($bound !== null) {
            return $bound;
        }
    }

    return null;
}

/**
 * Over HTTP/1.1, with no header curl adds but Host, so that $headBytes is the size of the request line and the headers
 * as Caddy reads them; a probe of 0 bytes carries no padding. The query names the request in the log PHP writes.
 *
 * @return array{status: int, reached_php: bool}
 */
function request_limits_send(
    string $site,
    string $ca,
    string $path,
    string $method,
    int $headBytes,
    int $bodyBytes = 0,
    bool $chunked = false,
): array {
    $probe = bin2hex(random_bytes(8));
    $target = sprintf('%s?request-limits=%s', $path, $probe);
    $headers = ['User-Agent:', 'Accept:'];
    $body = [];
    $file = null;
    if ($bodyBytes > 0) {
        $file = tempnam(sys_get_temp_dir(), 'request-limits-');
        file_put_contents($file, 'a=' . str_repeat('x', $bodyBytes - 2));
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        if ($chunked) {
            $headers[] = 'Transfer-Encoding: chunked';
        }
        $body = ['--data-binary', '@' . $file];
    }
    if ($headBytes > 0) {
        $padding = $headBytes - strlen(sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", $method, $target, $site));
        for ($index = 0; $padding > 0; ++$index) {
            $name = sprintf('X-Pad-%d: ', $index);
            $rest = $padding - strlen($name) - 2;
            // 32 bytes short of the rest, or what is left could be too short to be a header line of its own.
            $length = $rest <= 8192 ? $rest : min(8192, $rest - 32);
            $headers[] = $name . str_repeat('a', $length);
            $padding -= strlen($name) + $length + 2;
        }
    }
    $arguments = ['curl', '--silent', '--http1.1', '--cacert', $ca, '--output', '/dev/null', '--write-out', '%{http_code}', '--request', $method];
    foreach ($headers as $header) {
        $arguments[] = '--header';
        $arguments[] = $header;
    }
    $curl = run(
        [...$arguments, ...$body, sprintf('https://%s%s', $site, $target)],
        context: context()->withQuiet()->withAllowFailure(),
    );
    if ($file !== null) {
        unlink($file);
    }
    $logged = run(
        ['docker', 'compose', 'exec', '-T', 'op', 'grep', '-c', 'request-limits=' . $probe, 'var/log/dev.log'],
        context: context()->withQuiet()->withAllowFailure(),
    );

    return ['status' => (int) trim($curl->getOutput()), 'reached_php' => (int) trim($logged->getOutput()) > 0];
}

function request_limits_expect(bool $condition, string $what): void
{
    if (! $condition) {
        io()->error('Not measured: ' . $what);
        exit(1);
    }
    io()->text(' <info>✓</info> ' . $what);
}
