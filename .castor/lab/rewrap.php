<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Process\Process;

const REWRAP_CA_FILE = 'var/caddy-root.crt';

const REWRAP_LOGINS = 10;

const REWRAP_AFTER = 5;

const REWRAP_WORKER_TIMEOUT = 30;

/**
 * In no particular order: the direction of a move is read from the store.
 */
const REWRAP_CLIENTS = ['op', 'second'];

#[AsTask(
    description: 'Move the data keys of the tenant from one KMS client to another while logins are played: no login fails, the keys end up on the other client, and not one sealed value is read or rewritten',
)]
function rewrap_live(
    #[AsOption(description: 'How many complete logins to play around the move')]
    int $logins = REWRAP_LOGINS,
): int {
    io()->title('The data keys move while the provider serves');

    $env = load_dot_env(getcwd() . '/apps/beffroi/.env');
    foreach (['BEFFROI_ISSUER', 'BEFFROI_DEV_USER_PASSWORD', 'OIDC_DEMO_SECRET'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));

            exit(1);
        }
    }
    if (($env['BEFFROI_KMS_DSN_SECOND'] ?? '') === '') {
        io()->error([
            'There is no second KMS client to move the keys to, so there is nothing this walk can play.',
            'A rewrap is a run with both clients configured at once, and the second one has to hold a key under the id the deployment names. Run "castor provision --kms sodium" or "castor provision --kms vault", which write BEFFROI_KMS_DSN_SECOND, a sodium key under that id; LocalStack holds a key its container creates under an alias.',
        ]);

        exit(1);
    }

    $running = compose_running_services();
    foreach (['op', 'worker', 'database'] as $service) {
        if (! in_array($service, $running, true)) {
            io()->error(sprintf('The %s container is not running: "castor start" starts the stack.', $service));

            exit(1);
        }
    }

    $issuer = $env['BEFFROI_ISSUER'];
    $password = $env['BEFFROI_DEV_USER_PASSWORD'];
    $secret = $env['OIDC_DEMO_SECRET'];
    $ca = caddy_ca(getcwd() . '/' . REWRAP_CA_FILE);

    // Before the keys are read: a scope gets its key the first time something is sealed under it, and a login, or the
    // worker after it, is the first to seal under some.
    cost_journey($issuer, $password, $secret, $ca);
    io()->text('  a login before the keys are read went through');
    rewrap_wait_for_the_worker();
    io()->text('  the worker handled what that login sent it');

    $keysBefore = rewrap_keys();
    if ($keysBefore === []) {
        io()->error('A login went through and the tenant holds no data key, so there is nothing to move.');

        exit(1);
    }
    [$from, $to] = rewrap_direction(array_values(array_unique(array_values($keysBefore))));
    $sealedBefore = rewrap_sealed_columns();
    if ($sealedBefore === []) {
        io()->error('No sealed column of beffroi_user holds anything, so a comparison before and after would compare nothing: run "castor provision".');

        exit(1);
    }

    io()->definitionList(
        ['Keys' => sprintf('%d scope(s), wrapped by "%s"', count($keysBefore), implode('", "', array_unique(array_values($keysBefore))))],
        ['Sealed' => sprintf('%d column value(s) of beffroi_user, read as bytes', count($sealedBefore))],
        ['Logins' => sprintf('%d, the move started after the %d%s', $logins, REWRAP_AFTER, REWRAP_AFTER === 1 ? 'st' : 'th')],
        ['Move' => sprintf('"%s" to "%s", the direction the store leaves available', $from, $to)],
    );

    io()->section('What is played');

    $started = microtime(true);
    $move = null;
    $moveStarted = null;
    $moveEnded = null;

    for ($played = 1; $played <= $logins; ++$played) {
        if ($played === (REWRAP_AFTER + 1)) {
            $move = rewrap_start($from, $to);
            $moveStarted = microtime(true);
            io()->text(sprintf('  the move is started, the provider having served %d login(s)', $played - 1));
        }

        cost_journey($issuer, $password, $secret, $ca);
        io()->text(sprintf('  login %d of %d went through', $played, $logins));

        if ($move !== null && $moveEnded === null && ! $move->isRunning()) {
            $moveEnded = microtime(true);
            rewrap_check($move);
            io()->text(sprintf('  the move is done, after %.2f s, the provider having kept serving', $moveEnded - $moveStarted));
        }
    }

    if ($move === null) {
        io()->error(sprintf('The move was never started: %d login(s) is fewer than the %d this walk starts it after.', $logins, REWRAP_AFTER));

        exit(1);
    }
    if ($moveEnded === null) {
        $move->wait();
        $moveEnded = microtime(true);
        rewrap_check($move);
    }

    io()->section('What is true afterwards');

    $keysAfter = rewrap_keys();
    $sealedAfter = rewrap_sealed_columns();
    $findings = [];

    if (array_keys($keysBefore) !== array_keys($keysAfter)) {
        $findings[] = 'The scopes are not the ones they were: a rewrap moves the wrapping of a key and never the key, so no scope appears and none goes away.';
    }
    foreach ($keysAfter as $scope => $client) {
        if ($client !== $to) {
            $findings[] = sprintf('The key of scope "%s" is still wrapped by "%s".', $scope, $client);
        }
    }
    if ($sealedBefore !== $sealedAfter) {
        foreach ($sealedBefore as $where => $bytes) {
            if (($sealedAfter[$where] ?? null) !== $bytes) {
                $findings[] = sprintf('%s does not hold the bytes it held: a rewrap that moved a payload would be a rewrap that read one.', $where);
            }
        }
    }

    $remaining = rewrap_dry_run($from, $to);
    if ($remaining !== 0) {
        $findings[] = sprintf('A dry run from "%s" still lists %d key(s), so the move is not complete.', $from, $remaining);
    }

    cost_journey($issuer, $password, $secret, $ca);
    io()->text('  a login after the move went through');

    io()->table(['What', 'Measured'], [
        ['Logins played', sprintf('%d, none failed', $logins + 2)],
        ['The move', sprintf('%.2f s, between login %d and login %d', $moveEnded - $moveStarted, REWRAP_AFTER, REWRAP_AFTER + 1)],
        ['The walk', sprintf('%.1f s', microtime(true) - $started)],
        ['Keys', sprintf('%d scope(s), now wrapped by "%s"', count($keysAfter), $to)],
        ['Sealed values', sprintf('%d compared byte by byte', count($sealedBefore))],
        [sprintf('Dry run from "%s"', $from), 'lists nothing'],
    ]);

    if ($findings !== []) {
        io()->error($findings);

        return 1;
    }

    io()->success(sprintf(
        'The data keys of the tenant moved from "%s" to "%s" in %.2f s while the provider served %d login(s), not one of which failed, and the %d sealed value(s) of beffroi_user hold the bytes they held. A scope minted from now on is wrapped by the client the provider seals with, which this walk does not change; the keys stay on "%s", which is where the next run of it starts.',
        $from,
        $to,
        $moveEnded - $moveStarted,
        $logins + 2,
        count($sealedBefore),
        $to,
    ));

    return 0;
}

/**
 * @param list<string> $holding the clients that wrap a key today, each once
 *
 * @return array{string, string} the client to move from, then the one to move to
 */
function rewrap_direction(array $holding): array
{
    if (count($holding) !== 1) {
        io()->error([
            sprintf(
                'The data keys of the tenant are wrapped by %d client(s) at once ("%s"), so there is no single move to play.',
                count($holding),
                implode('", "', $holding),
            ),
            sprintf('Put them all on one client first ("castor console beffroi:data-keys:rewrap --to=%s"), then run this again.', REWRAP_CLIENTS[0]),
        ]);

        exit(1);
    }

    $from = $holding[0];
    if (! in_array($from, REWRAP_CLIENTS, true)) {
        io()->error([
            sprintf(
                'The data keys are wrapped by "%s", which is not one of the two clients this walk moves between ("%s").',
                $from,
                implode('", "', REWRAP_CLIENTS),
            ),
            'Either the deployment declares other clients than config/packages/key_management.yaml does, in which case REWRAP_CLIENTS is what to change, or a key was wrapped by a client that has gone.',
        ]);

        exit(1);
    }

    return $from === REWRAP_CLIENTS[0] ? [$from, REWRAP_CLIENTS[1]] : [$from, REWRAP_CLIENTS[0]];
}

/**
 * Not waited for: the logins carry on in the caller while the move runs.
 */
function rewrap_start(string $from, string $to): Process
{
    $process = new Process([
        'docker',
        'compose',
        'exec',
        '-T',
        'op',
        'bin/console',
        'beffroi:data-keys:rewrap',
        '--to=' . $to,
        '--from=' . $from,
        '--no-interaction',
    ], getcwd());
    $process->setTimeout(120.0);
    $process->start();

    return $process;
}

function rewrap_check(Process $process): void
{
    if ($process->isSuccessful()) {
        return;
    }

    io()->error([
        'The move failed, so nothing below says anything about a provider that kept serving.',
        trim($process->getErrorOutput() ?: $process->getOutput()),
    ]);

    exit(1);
}

/**
 * The lanes of the stack are queues of its database, where a message stays until the worker has handled it; one put
 * back for a later retry is not waited for.
 */
function rewrap_wait_for_the_worker(): void
{
    $deadline = microtime(true) + REWRAP_WORKER_TIMEOUT;
    while (rewrap_query("SELECT count(*) FROM messenger_messages WHERE queue_name <> 'failed' AND available_at <= now() AT TIME ZONE 'UTC'") !== ['0']) {
        if (microtime(true) >= $deadline) {
            io()->error(sprintf(
                'The worker has not emptied its queues within %d s of the login above, so a key it mints for that login could be minted during the walk: "castor logs worker" says what it is doing.',
                REWRAP_WORKER_TIMEOUT,
            ));

            exit(1);
        }
        usleep(200_000);
    }
}

function rewrap_dry_run(string $from, string $to): int
{
    $output = op_console(
        ['beffroi:data-keys:rewrap', '--to=' . $to, '--from=' . $from, '--dry-run', '--no-interaction'],
        context()->withQuiet(),
    )->getOutput();

    if (preg_match('/(\d+) data key\(s\) would move/', $output, $matches) === 1) {
        return (int) $matches[1];
    }

    return str_contains($output, 'holds no data key wrapped by') ? 0 : -1;
}

/**
 * Read in the table rather than through a command, which reports what it decides to report.
 *
 * @return array<string, string> the client, by scope
 */
function rewrap_keys(): array
{
    $keys = [];
    foreach (rewrap_query('SELECT scope, client FROM beffroi_data_key ORDER BY scope ASC') as $line) {
        [$scope, $client] = explode('|', $line, 2);
        $keys[$scope] = $client;
    }

    return $keys;
}

/**
 * A sealed column is a binary one under PostgreSQL.
 *
 * @return array<string, string> the bytes in hexadecimal, by "subject.column"
 */
function rewrap_sealed_columns(): array
{
    $columns = rewrap_query("SELECT column_name FROM information_schema.columns WHERE table_name = 'beffroi_user' AND data_type = 'bytea' ORDER BY column_name ASC");
    if ($columns === []) {
        return [];
    }

    $selects = [];
    foreach ($columns as $column) {
        $selects[] = sprintf(
            "SELECT subject || '.%s' AS where_, encode(%s, 'hex') AS bytes_ FROM beffroi_user WHERE %s IS NOT NULL",
            $column,
            $column,
            $column,
        );
    }

    $held = [];
    foreach (rewrap_query(implode(' UNION ALL ', $selects) . ' ORDER BY where_ ASC') as $line) {
        [$where, $bytes] = explode('|', $line, 2);
        $held[$where] = $bytes;
    }

    return $held;
}

/**
 * @return list<string> one line per row, fields separated by a pipe
 */
function rewrap_query(string $sql): array
{
    $process = run(
        [
            'docker',
            'compose',
            'exec',
            '-T',
            'database',
            'psql',
            '-U',
            rewrap_setting('user'),
            '-d',
            rewrap_setting('database'),
            '-t',
            '-A',
            '-F',
            '|',
            '-c',
            $sql,
        ],
        context: context()->withQuiet()->withAllowFailure(),
    );

    if (! $process->isSuccessful()) {
        io()->error(sprintf('The database could not be read: %s', trim($process->getErrorOutput())));

        exit(1);
    }

    $lines = [];
    foreach (explode("\n", trim($process->getOutput())) as $line) {
        $line = trim($line);
        if ($line !== '') {
            $lines[] = $line;
        }
    }

    return $lines;
}

function rewrap_setting(string $key): string
{
    $value = $_SERVER[sprintf('POSTGRES_%s', strtoupper($key))] ?? null;

    return is_string($value) && $value !== '' ? $value : 'beffroi';
}
