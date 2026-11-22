<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\InteractionPages;
use App\Http\LoginTarget;
use App\Http\RecentLogin;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Environment;

final class RecentLoginTest extends TestCase
{
    private const string NOW = '2026-10-10T12:00:00+00:00';

    /**
     * OIDC Core §2
     */
    #[Test]
    #[DataProvider('provideMomentsOfTheNewestProof')]
    public function aProofInsideTheWindowIsRecentAndOneOutsideItIsNot(string $provenAt, bool $recent): void
    {
        // Given
        $session = self::sessionProvenAt(new DateTimeImmutable($provenAt));

        // When / Then
        static::assertSame($recent, $this->recentLogin()->isRecent($session));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideMomentsOfTheNewestProof(): iterable
    {
        yield 'this second' => [self::NOW, true];
        yield 'a second short of the window' => ['2026-10-10T11:55:01+00:00', true];
        yield 'the window to the second' => ['2026-10-10T11:55:00+00:00', false];
        yield 'an hour ago' => ['2026-10-10T11:00:00+00:00', false];
    }

    #[Test]
    public function aSessionThatProvedSomethingInsideTheWindowIsSentNowhere(): void
    {
        // Given
        $session = self::sessionProvenAt(new DateTimeImmutable(self::NOW));

        // When / Then
        static::assertNull($this->recentLogin()->orSendToLogin(self::request(), $session, 'a_route'));
    }

    #[Test]
    public function aSessionThatProvedNothingRecentlyIsRememberedAndSentToTheLogin(): void
    {
        // Given
        $session = self::sessionProvenAt(new DateTimeImmutable('2026-10-10T11:00:00+00:00'));
        $request = self::request();

        // When
        $response = $this->recentLogin()->orSendToLogin($request, $session, 'a_route', [
            'a' => 'b',
        ]);

        // Then
        static::assertNotNull($response);
        static::assertSame(
            [
                'route' => 'a_route',
                'parameters' => [
                    'a' => 'b',
                ],
                'step_up' => null,
            ],
            $request->getSession()->get(LoginTarget::SESSION_KEY),
        );
    }

    private function recentLogin(): RecentLogin
    {
        $urls = static::createStub(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturn('/login');

        return new RecentLogin(
            new LoginTarget(new InteractionPages(static::createStub(Environment::class), $urls)),
            new MockClock(self::NOW),
        );
    }

    private static function sessionProvenAt(DateTimeImmutable $provenAt): AuthenticationSession
    {
        return Fixtures::session(authenticatedAt: $provenAt);
    }

    private static function request(): Request
    {
        $request = Request::create('/account/password');
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }
}
