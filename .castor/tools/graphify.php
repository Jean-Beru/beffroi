<?php

declare(strict_types=1);

/*
 * The knowledge graph of the repository (graphify): tree-sitter over the code, a model over the documents,
 * and a graph the agents and the maintainer query about the whole monorepo at once. It reads the sources
 * and never the running stack, and it writes graphify-out/, which git ignores: graph.json, the report
 * GRAPH_REPORT.md and the page graph.html, whose bubbles are the communities the model named.
 *
 * The semantic half needs a model. It is asked of the Claude Code CLI, billed to the subscription, rather
 * than of an API key, and that choice is what these tasks carry: the backend is named explicitly because
 * graphify never selects it on its own, and ANTHROPIC_API_KEY is removed from the environment because the
 * CLI gives a key precedence over the claude.ai login and a key without credit then fails every chunk.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * The extras of the Python package, named in full at every install: they are not cumulative, so an install
 * that omits one removes it. "anthropic" is the API backend, "terraform" the tree-sitter grammar of the
 * .hcl files, "mcp" the graphify-mcp server, "leiden" the community detection that Louvain replaces when
 * it is absent.
 */
const GRAPHIFY_EXTRAS = ['anthropic', 'terraform', 'mcp', 'leiden'];

/**
 * The backend of the semantic extraction. graphify excludes it from its own detection (detect_backend()),
 * so a run that does not name it falls back to the API key.
 */
const GRAPHIFY_BACKEND = 'claude-cli';

/**
 * What that backend asks the CLI for. Its own default is Opus, more than the structured JSON extraction
 * graphify performs over the documents of the repository needs.
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

    graphify_label($model, true);

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
 * Runs a graphify command that writes the graph. A failure is a failure of the task, reported as such.
 *
 * @param array<string> $arguments
 */
function graphify_run(array $arguments, string $model = GRAPHIFY_MODEL): void
{
    run(graphify_command($arguments, $model), context: context()->withTimeout(null));
}

/**
 * Runs a graphify command that reads the graph, and carries its exit code without adding to its output: a
 * question the graph cannot answer is answered by graphify itself, naming the nodes that were ambiguous or
 * the graph that is missing, and a task that framed that as its own error would bury the answer.
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
 * The command line of every task: graphify against this repository whatever directory castor was started
 * from, the corpus named by its absolute path and the output directory by GRAPHIFY_OUT, which every
 * graphify command reads, so a task called from a package of the monorepo writes and queries the one graph
 * at the root.
 *
 * "env -u" is what removes the API key for the child process only; the key stays in the shell that called.
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

/**
 * The root of the repository, the directory castor.php lives in, and the corpus graphify indexes.
 */
function graphify_root(): string
{
    return dirname(__DIR__, 2);
}

/**
 * Where the graph is written and read, absolute so that no command depends on the working directory.
 */
function graphify_out(): string
{
    return graphify_root() . '/graphify-out';
}
