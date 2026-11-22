<?php

declare(strict_types=1);

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * Named in full at every install: extras are not cumulative, and an install that omits one removes it.
 */
const GRAPHIFY_EXTRAS = ['anthropic', 'terraform', 'mcp', 'leiden'];

/**
 * Named on every run: graphify never detects it (detect_backend()) and would fall back to the API key.
 */
const GRAPHIFY_BACKEND = 'claude-cli';

/**
 * The CLI defaults to Opus, more than the structured extraction needs.
 */
const GRAPHIFY_MODEL = 'claude-sonnet-5';

#[AsTask(description: 'Install graphify and its extras, and copy the skill where Claude Code reads it')]
function graphify_install(): void
{
    io()->title('Installing graphify');

    if (trim((string) shell_exec('command -v uv')) === '') {
        io()->error('uv is not on the PATH: https://docs.astral.sh/uv/getting-started/installation/');
        exit(1);
    }

    run(['uv', 'tool', 'install', sprintf('graphifyy[%s]', implode(',', GRAPHIFY_EXTRAS)), '--force']);
    run(['graphify', 'install', '--platform', 'claude']);

    io()->success('graphify installed, and the skill is the one of this version');
}

#[AsTask(
    description: 'Build the graph of the repository: tree-sitter over the code, the CLI backend over the documents, then the communities named and the page and the report written with them',
)]
function graphify_build(
    #[AsOption(description: 'The model the CLI backend asks for')]
    string $model = GRAPHIFY_MODEL,
    #[AsOption(description: 'Index the code only: no model call, no document in the graph, and the communities keep their number for a name')]
    bool $codeOnly = false,
): void {
    io()->title('Building the graph');

    $arguments = ['extract', graphify_root(), '--backend', GRAPHIFY_BACKEND];
    if ($codeOnly) {
        $arguments[] = '--code-only';
    }

    graphify_run($arguments, $model);

    if ($codeOnly) {
        io()->success(sprintf('%s/graph.json written', graphify_out()));

        return;
    }

    // Every community is named again: the extraction renumbered them, so a kept name would label another set.
    graphify_label($model);

    io()->success(sprintf('%s holds graph.json, GRAPH_REPORT.md and graph.html', graphify_out()));
}

#[AsTask(
    description: 'Name the communities of the graph with the CLI backend, and rewrite the report and the page with the names',
)]
function graphify_label(
    #[AsOption(description: 'The model the CLI backend asks for')]
    string $model = GRAPHIFY_MODEL,
    #[AsOption(description: 'Keep the names already given and name only the communities that have none')]
    bool $missingOnly = false,
): void {
    io()->title('Naming the communities');

    $arguments = ['label', graphify_root(), '--backend=' . GRAPHIFY_BACKEND];
    if ($missingOnly) {
        $arguments[] = '--missing-only';
    }

    graphify_run($arguments, $model);
}

#[AsTask(
    description: 'Write the graph in one of the shapes graphify exports: html, callflow-html, obsidian, wiki, svg, graphml',
)]
function graphify_export(string $format): void
{
    io()->title(sprintf('Exporting the graph as %s', $format));

    graphify_run(['export', $format]);
}

#[AsTask(description: 'Re-extract the code files that changed and update the graph, without a model call')]
function graphify_update(): void
{
    io()->title('Updating the graph');

    graphify_run(['update', graphify_root()]);

    io()->success(sprintf('%s/graph.json updated', graphify_out()));
}

#[AsTask(description: 'Ask the graph a question, by traversal of the nodes it connects')]
function graphify_query(
    string $question,
    #[AsOption(description: 'Cap the answer at this many tokens')]
    int $budget = 2000,
    #[AsOption(description: 'Trace one path (depth first) instead of the broad context (breadth first)')]
    bool $dfs = false,
): void {
    $arguments = ['query', $question, '--budget', (string) $budget];
    if ($dfs) {
        $arguments[] = '--dfs';
    }

    graphify_read($arguments);
}

#[AsTask(description: 'Explain one node of the graph and its neighbours in plain language')]
function graphify_explain(string $node): void
{
    graphify_read(['explain', $node]);
}

#[AsTask(description: 'The shortest path the graph holds between two nodes')]
function graphify_path(string $from, string $to): void
{
    graphify_read(['path', $from, $to]);
}

#[AsTask(description: 'The most connected nodes of the graph, the architectural hubs')]
function graphify_god_nodes(
    #[AsOption(description: 'How many nodes to show')]
    int $top = 10,
): void {
    graphify_read(['god-nodes', '--top', (string) $top]);
}

/**
 * @param array<string> $arguments
 */
function graphify_run(array $arguments, string $model = GRAPHIFY_MODEL): void
{
    run(graphify_command($arguments, $model), context: context()->withTimeout(null));
}

/**
 * Passes the exit code on and adds nothing to the output: graphify itself says what it could not answer.
 *
 * @param array<string> $arguments
 */
function graphify_read(array $arguments): void
{
    $result = run(
        graphify_command($arguments, GRAPHIFY_MODEL),
        context: context()->withTimeout(null)->withAllowFailure(),
    );
    if (! $result->isSuccessful()) {
        exit($result->getExitCode() ?? 1);
    }
}

/**
 * "env -u" drops the API key for the child only: the CLI would prefer it to the claude.ai login.
 *
 * @param array<string> $arguments
 *
 * @return array<string>
 */
function graphify_command(array $arguments, string $model): array
{
    if (trim((string) shell_exec('command -v graphify')) === '') {
        io()->error('graphify is not on the PATH: run "castor graphify-install" first.');
        exit(1);
    }

    return [
        'env',
        '-u',
        'ANTHROPIC_API_KEY',
        'GRAPHIFY_CLAUDE_CLI_MODEL=' . $model,
        'GRAPHIFY_OUT=' . graphify_out(),
        'graphify',
        ...$arguments,
    ];
}

function graphify_root(): string
{
    return dirname(__DIR__, 2);
}

function graphify_out(): string
{
    return graphify_root() . '/graphify-out';
}
