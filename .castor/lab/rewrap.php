<?php

declare(strict_types=1);

/*
 * The fourth success criterion of spike 8 (issue #410), the half only a stack that serves can answer: the
 * data keys of a tenant move from one KMS client to another while logins are being played, and no login
 * fails.
 *
 * What the suite proves beside this, deterministically and without a stack, is that every sealed column is
 * byte identical before and after the move, that a row whose data key was destroyed no longer opens and
 * names the key, and that a destruction reaches one tenant of two (DataKeysTest). Those needed two KMS
 * clients and a second tenant, which the test kernel has and which no configuration of one tenant shows.
 * What is left for here is the one word the criterion rests on, while it serves.
 *
 * The move is fast, a handful of rows and one call to the KMS per row, so what this proves is not a race:
 * it is that logins played before it, across it and after it all went through, that the keys ended up on
 * the other client, and that not one sealed value was read or rewritten on the way.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\load_dot_env;
use function Castor\run;
use Symfony\Component\Process\Process;

/**
 * Where the internal CA of Caddy is copied for the PHP of the host, as the other walks copy it: the OP
 * serves a certificate of an authority that exists only inside the stack.
 */
const REWRAP_CA_FILE = 'var/caddy-root.crt';

/**
 * How many complete logins a run plays. Enough that some are before the move, some across it and some
 * after, and few enough that a walk taken by hand stays under a minute.
 */
const REWRAP_LOGINS = 10;

/**
 * After which login the move is started. Halfway, so that what follows it is as long as what precedes it.
 */
const REWRAP_AFTER = 5;

/**
 * The clients the keys move between, as config/packages/key_management.yaml declares them.
 */
const REWRAP_FROM = 'op';

const REWRAP_TO = 'second';

#[AsTask(
    description: 'Move the data keys of the tenant from one KMS client to another while logins are played: no login fails, the keys end up on the other client, and not one sealed value is read or rewritten',
)]
function rewrap_live(
    #[AsOption(description: 'How many complete logins to play around the move')]
    int $logins = REWRAP_LOGINS,
): int {
    io()->title('The data keys move while the provider serves');

    $env = load_dot_env(getcwd() . '/apps/op/.env');
    foreach (['HEIDI_ISSUER', 'HEIDI_DEV_USER_PASSWORD', 'OIDC_DEMO_SECRET'] as $name) {
        if (($env[$name] ?? '') === '') {
            io()->error(sprintf('%s is empty: run "castor provision" first.', $name));

            exit(1);
        }
    }
    if (($env['HEIDI_KMS_DSN_SECOND'] ?? '') === '') {
        io()->error([
            'There is no second KMS client to move the keys to, so there is nothing this walk can play.',
            'A rewrap is a run with both clients configured at once, and the second one has to hold a key under the id the deployment names. Run "castor provision --kms sodium", which writes HEIDI_KMS_DSN_SECOND; the Vault and LocalStack backends hold a key a container creates and not one a task generates, and moving to Vault waits on heidi#420 besides.',
        ]);

        exit(1);
    }

    $running = compose_running_services();
    foreach (['op', 'database'] as $service) {
        if (! in_array($service, $running, true)) {
            io()->error(sprintf('The %s container is not running: "castor start" starts the stack.', $service));

            exit(1);
        }
    }

    $issuer = $env['HEIDI_ISSUER'];
    $password = $env['HEIDI_DEV_USER_PASSWORD'];
    $secret = $env['OIDC_DEMO_SECRET'];
    $ca = caddy_ca(getcwd() . '/' . REWRAP_CA_FILE);

    $keysBefore = rewrap_keys();
    if ($keysBefore === []) {
        io()->error('The tenant holds no data key, so there is nothing to move: play a journey first ("castor demo --check") and run this again.');

        exit(1);
    }
    $sealedBefore = rewrap_sealed_columns();
    if ($sealedBefore === []) {
        io()->error('No sealed column of heidi_user holds anything, so a comparison before and after would compare nothing: run "castor provision" and play a journey.');

        exit(1);
    }

    io()->definitionList(
        ['Keys' => sprintf('%d scope(s), wrapped by "%s"', count($keysBefore), implode('", "', array_unique(array_values($keysBefore))))],
        ['Sealed' => sprintf('%d column value(s) of heidi_user, read as bytes', count($sealedBefore))],
        ['Logins' => sprintf('%d, the move started after the %d%s', $logins, REWRAP_AFTER, REWRAP_AFTER === 1 ? 'st' : 'th')],
        ['Move' => sprintf('"%s" to "%s"', REWRAP_FROM, REWRAP_TO)],
    );

    io()->section('What is played');

    $started = microtime(true);
    $move = null;
    $moveStarted = null;
    $moveEnded = null;

    for ($played = 1; $played <= $logins; ++$played) {
        if ($played === (REWRAP_AFTER + 1)) {
            $move = rewrap_start();
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
        if ($client !== REWRAP_TO) {
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

    $remaining = rewrap_dry_run();
    if ($remaining !== 0) {
        $findings[] = sprintf('A dry run from "%s" still lists %d key(s), so the move is not complete.', REWRAP_FROM, $remaining);
    }

    cost_journey($issuer, $password, $secret, $ca);
    io()->text('  a login after the move went through');

    io()->table(['What', 'Measured'], [
        ['Logins played', sprintf('%d, none failed', $logins + 1)],
        ['The move', sprintf('%.2f s, between login %d and login %d', $moveEnded - $moveStarted, REWRAP_AFTER, REWRAP_AFTER + 1)],
        ['The walk', sprintf('%.1f s', microtime(true) - $started)],
        ['Keys', sprintf('%d scope(s), now wrapped by "%s"', count($keysAfter), REWRAP_TO)],
        ['Sealed values', sprintf('%d compared byte by byte', count($sealedBefore))],
        ['Dry run from "' . REWRAP_FROM . '"', 'lists nothing'],
    ]);

    if ($findings !== []) {
        io()->error($findings);

        return 1;
    }

    io()->success(sprintf(
        'The data keys of the tenant moved from "%s" to "%s" in %.2f s while the provider served %d login(s), not one of which failed, and the %d sealed value(s) of heidi_user hold the bytes they held. Point the store at "%s" to have the keys it creates from now on wrapped there.',
        REWRAP_FROM,
        REWRAP_TO,
        $moveEnded - $moveStarted,
        $logins + 1,
        count($sealedBefore),
        REWRAP_TO,
    ));

    return 0;
}

/**
 * The move, started and not waited for: the point of the walk is that the provider keeps serving while it
 * runs, so the logins carry on in the caller.
 */
function rewrap_start(): Process
{
    $process = new Process([
        'docker',
        'compose',
        'exec',
        '-T',
        'op',
        'bin/console',
        'heidi:data-keys:rewrap',
        '--to=' . REWRAP_TO,
        '--from=' . REWRAP_FROM,
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
 * How many keys a dry run from the old client still lists, which is what says the move is complete.
 */
function rewrap_dry_run(): int
{
    $output = op_console(
        ['heidi:data-keys:rewrap', '--to=' . REWRAP_TO, '--from=' . REWRAP_FROM, '--dry-run', '--no-interaction'],
        context()->withQuiet(),
    )->getOutput();

    if (preg_match('/(\d+) data key\(s\) would move/', $output, $matches) === 1) {
        return (int) $matches[1];
    }

    // The command says so in words when the tenant holds nothing wrapped by that client.
    return str_contains($output, 'holds no data key wrapped by') ? 0 : -1;
}

/**
 * The client that wraps each scope of the tenant, read in the table and not in a command: what a command
 * reports of the rows is what a command decides to report.
 *
 * @return array<string, string> the client, by scope
 */
function rewrap_keys(): array
{
    $keys = [];
    foreach (rewrap_query('SELECT scope, client FROM heidi_data_key ORDER BY scope ASC') as $line) {
        [$scope, $client] = explode('|', $line, 2);
        $keys[$scope] = $client;
    }

    return $keys;
}

/**
 * Every sealed value of heidi_user as the database holds it, in hexadecimal.
 *
 * The columns are the binary ones of the table, which is what a sealed column is under PostgreSQL, so a
 * column sealed later is compared without this walk being touched. The rows are named by their subject,
 * which is in the clear by construction and which no rewrap touches.
 *
 * @return array<string, string> the bytes, by "subject.column"
 */
function rewrap_sealed_columns(): array
{
    $columns = rewrap_query("SELECT column_name FROM information_schema.columns WHERE table_name = 'heidi_user' AND data_type = 'bytea' ORDER BY column_name ASC");
    if ($columns === []) {
        return [];
    }

    $selects = [];
    foreach ($columns as $column) {
        $selects[] = sprintf(
            "SELECT subject || '.%s' AS where_, encode(%s, 'hex') AS bytes_ FROM heidi_user WHERE %s IS NOT NULL",
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
 * One line per row, fields separated by a pipe, read with psql in the container of the database.
 *
 * @return list<string>
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

    return is_string($value) && $value !== '' ? $value : 'heidi';
}
