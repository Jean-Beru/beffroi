<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use function array_filter;
use function array_shift;
use ArrayObject;
use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Provider\ProviderMetadataReader;
use Beffroi\Tui\Screen\Administration;
use Beffroi\Tui\Screen\Shell;
use Beffroi\Tui\Screen\ThisProgram;
use Beffroi\Tui\SignIn\BrowserInterface;
use Beffroi\Tui\SignIn\SignIn;
use Beffroi\Tui\Tests\Fixture\FakeGitHub;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\Programs;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Text\Catalogue;
use Beffroi\Tui\Wiring;
use Closure;
use function count;
use DateTimeImmutable;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Revolt\EventLoop;
use function str_contains;
use function str_ends_with;
use function str_repeat;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Tui\Terminal\ScreenBuffer;
use Symfony\Component\Tui\Terminal\VirtualTerminal;
use Symfony\Component\Tui\Tui;

/**
 * The home page waits for the administrator: nothing is asked of the provider before Enter, which starts the
 * sign-in, and starts it again once one failed.
 */
final class AdministrationTest extends TestCase
{
    private const int COLUMNS = 100;

    private const int ROWS = 30;

    private VirtualTerminal $terminal;

    private RecordedRequests $http;

    /**
     * @var ArrayObject<int, string> the addresses the browser was opened on
     */
    private ArrayObject $opened;

    /**
     * @var ArrayObject<int, MockResponse> what the pushed authorization request endpoint answers, in turn
     */
    private ArrayObject $pushes;

    /**
     * @var list<string> the watchers of the event loop a test left, cancelled once it ends
     */
    private array $watchers = [];

    protected function setUp(): void
    {
        $this->terminal = new VirtualTerminal(self::COLUMNS, self::ROWS);
        $this->opened = new ArrayObject();
        $pushes = $this->pushes = new ArrayObject();
        $this->http = RecordedRequests::routed(static function (string $method, string $url) use ($pushes): MockResponse {
            if (str_ends_with($url, '/.well-known/openid-configuration')) {
                return new MockResponse(json_encode(FakeProvider::metadataDocument(), JSON_THROW_ON_ERROR));
            }
            if (str_ends_with($url, '/par')) {
                $answers = $pushes->getArrayCopy();
                $answer = array_shift($answers);
                $pushes->exchangeArray($answers);

                return $answer ?? new MockResponse('', ['http_code' => 500]);
            }

            return new MockResponse('', ['http_code' => 404]);
        });
    }

    protected function tearDown(): void
    {
        foreach ($this->watchers as $watcher) {
            EventLoop::cancel($watcher);
        }
    }

    #[Test]
    public function theHomePageAsksNothingOfTheProviderBeforeTheAdministratorDoes(): void
    {
        // Given
        EventLoop::defer(fn (): null => $this->press('q'));

        // When
        $this->administer();

        // Then
        static::assertSame([], $this->http->requests);
    }

    #[Test]
    public function enterStartsTheSignInInTheBrowser(): void
    {
        // Given
        $this->pushes[] = self::pushed();
        EventLoop::defer(fn (): null => $this->press("\r"));

        // When
        $this->administer();

        // Then
        static::assertCount(1, $this->opened);
    }

    #[Test]
    public function enterStartsAgainASignInThatFailed(): void
    {
        // Given
        $this->pushes[] = new MockResponse('{"error":"invalid_request"}', ['http_code' => 400]);
        $this->pushes[] = self::pushed();
        EventLoop::defer(fn (): null => $this->press("\r"));
        $this->whenTheScreenShows('⏎  try again', fn (): null => $this->press("\r"));

        // When
        $this->administer();

        // Then
        static::assertSame(
            [2, 1],
            [count(array_filter($this->http->requests, static fn (array $request): bool => str_ends_with($request['url'], '/par'))), count($this->opened)],
        );
    }

    #[Test]
    public function theHomePageNamesANewerReleaseOnceTheScreenHasStarted(): void
    {
        // Given
        $seen = new ArrayObject();
        $this->whenTheScreenShows('0.1.1', function () use ($seen): null {
            $seen[] = true;

            return $this->press('q');
        });

        // When
        $this->administer(Programs::release('0.1.0', FakeGitHub::serving('0.1.1', str_repeat('0', 64))));

        // Then
        static::assertCount(1, $seen);
    }

    private static function pushed(): MockResponse
    {
        return new MockResponse('{"request_uri":"urn:ietf:params:oauth:request_uri:r","expires_in":60}', ['http_code' => 201]);
    }

    /**
     * Runs the screen until it is quit: the browser quits it once it was opened, and it is quit after five seconds
     * whatever happened, so that a test that fails does not hold the suite.
     */
    private function administer(?ThisProgram $program = null): void
    {
        $quit = fn (): null => $this->press('q');
        $browser = new readonly class($this->opened, $quit) implements BrowserInterface {
            /**
             * @param ArrayObject<int, string> $opened
             * @param Closure(): null $then
             */
            public function __construct(
                private ArrayObject $opened,
                private Closure $then,
            ) {
            }

            public function open(string $url): void
            {
                $this->opened[] = $url;
                EventLoop::defer($this->then);
            }
        };
        $clock = new MockClock(new DateTimeImmutable('@' . FakeProvider::NOW));
        $this->watchers[] = EventLoop::delay(5, $quit);
        new Administration(
            new SignIn(new ProviderMetadataReader($this->http->client), $this->http->client, $clock, $browser, '<p>back</p>'),
            new Shell(Catalogue::translator('en'), $clock, Wiring::sections(), false, $program ?? Programs::fromItsSources()),
            'en',
        )->run(new Tui(Shell::styleSheet(), $this->terminal), FakeProvider::profile(SigningKey::generate()), 'default');
    }

    /**
     * @param Closure(): null $then
     */
    private function whenTheScreenShows(string $text, Closure $then): void
    {
        $this->watchers[] = EventLoop::repeat(0.01, function (string $watcher) use ($text, $then): void {
            $buffer = new ScreenBuffer(self::COLUMNS, self::ROWS);
            $buffer->write($this->terminal->getOutput());
            if (str_contains($buffer->getScreen(), $text)) {
                EventLoop::cancel($watcher);
                $then();
            }
        });
    }

    private function press(string $key): null
    {
        $this->terminal->simulateInput($key);

        return null;
    }
}
