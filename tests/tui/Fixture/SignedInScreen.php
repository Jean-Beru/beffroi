<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use function Amp\delay;
use function array_filter;
use Beffroi\Tui\Screen\SectionInterface;
use Beffroi\Tui\Screen\Shell;
use Beffroi\Tui\Text\Catalogue;
use Beffroi\Tui\Wiring;
use Closure;
use function count;
use DateTimeImmutable;
use function is_array;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use LogicException;
use function mb_str_split;
use function sprintf;
use function str_repeat;
use function str_starts_with;
use function strlen;
use function substr;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Tui\Terminal\ScreenBuffer;
use Symfony\Component\Tui\Terminal\VirtualTerminal;
use Symfony\Component\Tui\Tui;

/**
 * The screen of an administrator signed in at the fake provider, in a terminal large enough for a section, its
 * administration API answering each path, query included, with what a test gives it, and any other one with a 404
 * "not_found". What a section reads runs on the event loop: every key pressed lets it answer before the screen is
 * read.
 */
final readonly class SignedInScreen
{
    public const int COLUMNS = 140;

    public const int ROWS = 70;

    public VirtualTerminal $terminal;

    public Tui $tui;

    public Shell $shell;

    public RecordedRequests $http;

    /**
     * @var list<SectionInterface>
     */
    private array $sections;

    /**
     * @param array<string, array<string, mixed>|Closure(): MockResponse> $answers the document each path of the API answers to a GET, or the response, and to another method under the method, a space and the path
     * @param array<string, mixed> $tokens the answer of the token endpoint the session holds
     */
    public function __construct(
        array $answers,
        bool $colours = false,
        array $tokens = [],
        private int $columns = self::COLUMNS,
        private int $rows = self::ROWS,
    ) {
        $this->http = RecordedRequests::routed(static function (string $method, string $url) use ($answers): MockResponse {
            $path = substr($url, strlen(FakeProvider::ADMINISTRATION));
            $answer = str_starts_with($url, FakeProvider::ADMINISTRATION) ? $answers[$method === 'GET' ? $path : $method . ' ' . $path] ?? null : null;
            if ($answer instanceof Closure) {
                return $answer();
            }
            if (is_array($answer)) {
                return new MockResponse(json_encode($answer, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            }

            return new MockResponse('{"error":"not_found","error_description":"Nothing is served there."}', ['http_code' => 404]);
        });
        $this->terminal = new VirtualTerminal($this->columns, $this->rows);
        $this->tui = new Tui(Shell::styleSheet($colours), $this->terminal);
        $this->sections = Wiring::sections();
        $this->shell = new Shell(Catalogue::translator('en'), new MockClock(new DateTimeImmutable('@' . (FakeProvider::NOW + 60))), $this->sections, $colours);
        $this->shell->attachTo($this->tui);
        $this->tui->start();
        $this->shell->signedIn(Sessions::of($this->http->client, $tokens), $this->tui);
        $this->settle();
    }

    /**
     * The section of that label is chosen in the navigation, the focus staying there.
     */
    public function open(string $title): void
    {
        foreach ($this->sections as $index => $section) {
            if ($section->title() === $title) {
                $this->press(str_repeat("\e[B", $index));

                return;
            }
        }

        throw new LogicException(sprintf('No section is labelled "%s".', $title));
    }

    /**
     * The keys, one after the other, each answered before the next.
     *
     * @param list<string>|string $keys
     */
    public function press(array|string $keys): void
    {
        foreach (is_array($keys) ? $keys : [$keys] as $key) {
            $this->terminal->simulateInput($key);
            $this->settle();
        }
    }

    public function type(string $text): void
    {
        foreach (mb_str_split($text) as $character) {
            $this->press($character);
        }
    }

    /**
     * What the terminal shows now.
     */
    public function screen(): string
    {
        $this->settle();
        $this->tui->processRender();
        $buffer = new ScreenBuffer($this->columns, $this->rows);
        $buffer->write($this->terminal->getOutput());

        return $buffer->getScreen();
    }

    /**
     * The requests sent to that path of the API, query included, with that method.
     */
    public function requestsTo(string $path, string $method = 'GET'): int
    {
        return count(array_filter(
            $this->http->requests,
            static fn (array $request): bool => $request['method'] === $method && $request['url'] === FakeProvider::ADMINISTRATION . $path,
        ));
    }

    public function stop(): void
    {
        $this->settle();
        $this->tui->stop();
    }

    /**
     * The event loop is let run what the keys started: a read of the API, and a refresh it waits for.
     */
    private function settle(): void
    {
        for ($turn = 0; $turn < 3; ++$turn) {
            delay(0);
        }
    }
}
