<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use function Amp\delay;
use Beffroi\Tui\Key\SigningKey;
use Beffroi\Tui\Protocol\ProviderRefusalException;
use Beffroi\Tui\Screen\Colourway;
use Beffroi\Tui\Screen\TerminalBackground;
use Beffroi\Tui\Screen\Shell;
use Beffroi\Tui\Screen\Symbol;
use Beffroi\Tui\Tests\Fixture\FakeGitHub;
use Beffroi\Tui\Tests\Fixture\FakeProvider;
use Beffroi\Tui\Tests\Fixture\Programs;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Tests\Fixture\Sessions;
use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use Beffroi\Tui\Text\Catalogue;
use Beffroi\Tui\Wiring;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function explode;
use function str_contains;
use function str_repeat;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\Tui\Terminal\ScreenBuffer;
use Symfony\Component\Tui\Terminal\VirtualTerminal;
use Symfony\Component\Tui\Tui;

/**
 * What the screen draws: the home page and where the sign-in stands, then the sections and what the selected one
 * shows, and nothing a third party wrote as anything but text.
 */
final class ShellTest extends TestCase
{
    private const int COLUMNS = 100;

    private const int ROWS = 30;

    private VirtualTerminal $terminal;

    private Tui $tui;

    private Shell $shell;

    protected function setUp(): void
    {
        $this->terminal = new VirtualTerminal(self::COLUMNS, self::ROWS);
        $this->tui = new Tui(Shell::styleSheet(), $this->terminal);
        $this->shell = new Shell(
            Catalogue::translator('en'),
            new MockClock(new DateTimeImmutable('@' . (FakeProvider::NOW + 60))),
            Wiring::sections(),
            true,
            Programs::fromItsSources(),
        );
        $this->shell->attachTo($this->tui);
    }

    /**
     * What a section started reading is let finish before the next test, whose event loop would run it.
     */
    protected function tearDown(): void
    {
        delay(0);
        $this->tui->stop();
    }

    #[Test]
    public function theHomePageNamesTheTaskTheInstanceAndTheProfile(): void
    {
        // When
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'staging');

        // Then
        $screen = $this->screen();
        static::assertSame(
            [true, true, true, true],
            [
                str_contains($screen, 'Administer the instance'),
                str_contains($screen, 'https://op.example'),
                str_contains($screen, 'Profile staging'),
                str_contains($screen, '⏎  sign in'),
            ],
        );
    }

    #[Test]
    public function theHomePageNamesTheBuildOfThisProgram(): void
    {
        // When
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');

        // Then
        static::assertStringContainsString('beffroi-tui, from its sources', $this->screen());
    }

    #[Test]
    public function aReleaseSaysOnTheHomePageThatItLooksForANewerOne(): void
    {
        // Given
        $shell = $this->releaseShell(FakeGitHub::serving('0.1.1', str_repeat('0', 64)));

        // When
        $shell->home(FakeProvider::profile(SigningKey::generate()), 'default');

        // Then
        static::assertStringContainsString('beffroi-tui 0.1.0 · looking for a newer release', $this->screen());
    }

    #[Test]
    public function theHomePageNamesTheNewerReleaseOnceTheReleasesAnswered(): void
    {
        // Given
        $shell = $this->releaseShell(FakeGitHub::serving('0.1.1', str_repeat('0', 64)));
        $shell->home(FakeProvider::profile(SigningKey::generate()), 'default');
        $this->tui->start();

        // When
        $shell->lookForANewerRelease($this->tui);

        // Then
        static::assertMatchesRegularExpression('/0\.1\.1 is out: beffroi-tui self-update/', $this->screen());
    }

    /**
     * Mono until the terminal says its background: the kit's own cut, drawn as the kit wrote it.
     */
    #[Test]
    public function theHomePageDrawsTheSymbolMonoFirst(): void
    {
        // When
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');

        // Then
        static::assertStringContainsString(explode("\n", Symbol::fitting(self::ROWS, 4)->drawn(Colourway::Mono))[1], $this->screen());
    }

    #[Test]
    public function theScreenAsksTheTerminalTheColourOfItsBackground(): void
    {
        // Given
        $this->screen();

        // When
        $this->shell->askTheBackground($this->tui);

        // Then
        static::assertStringContainsString(TerminalBackground::QUERY, $this->terminal->getOutput());
    }

    /**
     * The brand draws the tower in paper on a dark terminal (#F2F4F6).
     */
    #[Test]
    public function aDarkTerminalGetsTheSymbolInPaper(): void
    {
        // Given
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');
        $this->screen();
        $this->terminal->clearOutput();

        // When
        $this->terminal->simulateInput("\e]11;rgb:0c0c/1010/1616\e\\");

        // Then
        $this->screen();
        static::assertStringContainsString('242;244;246', $this->terminal->getOutput());
    }

    /**
     * https://no-color.org: without colours the symbol stays mono, and the terminal is asked nothing.
     */
    #[Test]
    public function aScreenWithoutColoursAsksTheTerminalNothing(): void
    {
        // Given
        $terminal = new VirtualTerminal(self::COLUMNS, self::ROWS);
        $tui = new Tui(Shell::styleSheet(), $terminal);
        $shell = new Shell(Catalogue::translator('en'), new MockClock(), Wiring::sections(), false, Programs::fromItsSources());
        $shell->attachTo($tui);
        $tui->start();

        // When
        $shell->askTheBackground($tui);

        // Then
        $tui->stop();
        static::assertStringNotContainsString(TerminalBackground::QUERY, $terminal->getOutput());
    }

    /**
     * A screen of its own in the terminal of the test, this program a release 0.1.0 whose releases GitHub answers.
     */
    private function releaseShell(RecordedRequests $github): Shell
    {
        $this->terminal = new VirtualTerminal(self::COLUMNS, self::ROWS);
        $this->tui = new Tui(Shell::styleSheet(), $this->terminal);
        $shell = new Shell(Catalogue::translator('en'), new MockClock(), Wiring::sections(), false, Programs::release('0.1.0', $github));
        $shell->attachTo($this->tui);

        return $shell;
    }

    /**
     * The address of the sign-in is a link to the whole of it (OSC 8), however the screen wraps it.
     */
    #[Test]
    public function whileTheBrowserIsAwaitedTheAddressOfTheSignInIsALink(): void
    {
        // Given
        $url = 'https://op.example/authorize?client_id=tui-client&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A' . str_repeat('r', 80);
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');
        $this->shell->reading(FakeProvider::profile(SigningKey::generate()));

        // When
        $this->shell->signingIn(FakeProvider::profile(SigningKey::generate()), $url);

        // Then
        $this->screen();
        static::assertStringContainsString("\e]8;;{$url}\e\\", $this->terminal->getOutput());
    }

    #[Test]
    public function onceSignedInTheScreenNamesTheAdministratorAndListsTheSections(): void
    {
        // When
        $this->shell->signedIn(Sessions::of(new MockHttpClient(), name: 'Ada Lovelace'), $this->tui);

        // Then
        $screen = $this->screen();
        static::assertSame(
            [true, true, true, true],
            [
                str_contains($screen, 'Ada Lovelace · phr'),
                str_contains($screen, 'Signing keys'),
                str_contains($screen, 'Monitoring'),
                str_contains($screen, 'https://op.example/par'),
            ],
        );
    }

    /**
     * A section that reads the administration API says it is reading it until the API answers.
     */
    #[Test]
    public function aSectionThatReadsTheApiSaysSoUntilItAnswers(): void
    {
        // Given
        $this->shell->signedIn(Sessions::of(new MockHttpClient()), $this->tui);
        $this->screen();

        // When
        $this->terminal->simulateInput("\e[B\e[B");

        // Then
        static::assertStringContainsString('Reading the administration API', $this->screen());
    }

    /**
     * Esc leaves a section for the navigation, rather than the screen.
     */
    #[Test]
    public function escGoesBackFromASectionToTheNavigation(): void
    {
        // Given
        $screen = new SignedInScreen([]);
        $screen->open('section.users');
        $screen->press("\t");

        // When
        $screen->press("\e");

        // Then
        $typing = $screen->shell->typing($screen->tui);
        $screen->stop();
        static::assertFalse($typing);
    }

    /**
     * Tab goes round the navigation and the widgets of the section shown.
     */
    #[Test]
    public function tabGoesRoundTheSectionAndBackToTheNavigation(): void
    {
        // Given
        $screen = new SignedInScreen([]);
        $screen->open('section.users');

        // When
        $screen->press("\t");
        $inTheSection = $screen->shell->typing($screen->tui);
        $screen->press("\t");
        $inItsOtherField = $screen->shell->typing($screen->tui);
        $screen->press("\t");

        // Then
        $typing = $screen->shell->typing($screen->tui);
        $screen->stop();
        static::assertSame([true, true, false], [$inTheSection, $inItsOtherField, $typing]);
    }

    /**
     * OIDC Core §3.1.2.6: a sign-in refused for its "acr" says what an administrator signs in with.
     */
    #[Test]
    public function aRefusalForTheClassOfTheAuthenticationSaysToSignInWithAPasskey(): void
    {
        // Given
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');

        // When
        $this->shell->failed(
            new ProviderRefusalException(
                'authorization endpoint',
                null,
                'unmet_authentication_requirements',
                'The end user did not authenticate as any requested acr value demands.',
            ),
        );

        // Then
        static::assertStringContainsString('An administrator signs in with a passkey', $this->screen());
    }

    /**
     * RFC 6749 §4.1.2.1, decision 0038: the provider denies the administration API to whoever does not administer the
     * tenant, and the screen says what makes an administrator.
     */
    #[Test]
    public function aDenialSaysWhatMakesAnAdministrator(): void
    {
        // Given
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');

        // When
        $this->shell->failed(
            new ProviderRefusalException(
                'authorization endpoint',
                null,
                'access_denied',
                'The end user does not administer the tenant whose administration API the request names.',
            ),
        );

        // Then
        static::assertStringContainsString('This account does not administer the instance', $this->screen());
    }

    #[Test]
    public function aRefusalThisProgramKnowsNothingAboutIsShownAlone(): void
    {
        // Given
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');

        // When
        $this->shell->failed(new ProviderRefusalException('authorization endpoint', null, 'temporarily_unavailable', null));

        // Then
        static::assertSame([true, false], [str_contains($this->screen(), '(temporarily_unavailable)'), str_contains($this->screen(), 'refusal.')]);
    }

    #[Test]
    public function aSignInThatFailedCanBeStartedAgain(): void
    {
        // Given
        $this->shell->home(FakeProvider::profile(SigningKey::generate()), 'default');

        // When
        $this->shell->failed(new ProviderRefusalException('pushed authorization request endpoint', 400, 'invalid_request', null));

        // Then
        static::assertStringContainsString('⏎  try again', $this->screen());
    }

    /**
     * Decision 0038: what a third party wrote is shown, and the terminal is handed none of it as a sequence.
     */
    #[Test]
    public function aNameThatCarriesAnEscapeSequenceIsDrawnAsText(): void
    {
        // When
        $this->shell->signedIn(Sessions::of(new MockHttpClient(), name: "Ada\e]0;owned\x07"), $this->tui);

        // Then
        static::assertSame([false, true], [str_contains($this->terminal->getOutput(), "\e]0;owned"), str_contains($this->screen(), 'Ada]0;owned')]);
    }

    private function screen(): string
    {
        if (! $this->tui->isRunning()) {
            $this->tui->start();
        }
        $this->tui->processRender();
        $buffer = new ScreenBuffer(self::COLUMNS, self::ROWS);
        $buffer->write($this->terminal->getOutput());

        return $buffer->getScreen();
    }
}
