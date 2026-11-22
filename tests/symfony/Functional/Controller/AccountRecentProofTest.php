<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\Account\AsksForARecentProofInterface;
use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\LoginTarget;
use App\Http\RecentLogin;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use function class_exists;
use DateInterval;
use function is_a;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use function str_ends_with;
use function str_replace;
use function str_starts_with;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.2
 */
final class AccountRecentProofTest extends PasskeyTestCase
{
    #[Test]
    public function everyPageOfTheAccountSaysWhetherItAsksForARecentProof(): void
    {
        // When
        $silent = [];
        $asking = [];
        $onTheSessionAlone = [];
        foreach (self::pagesOfTheAccount() as $name => $page) {
            if (is_a($page[2], AsksForARecentProofInterface::class, true)) {
                $asking[] = $name;
            } elseif (is_a($page[2], ReachedOnTheSessionAloneInterface::class, true)) {
                $onTheSessionAlone[] = $name;
            } else {
                $silent[] = sprintf('%s (%s)', $name, $page[2]);
            }
        }

        // Then
        static::assertSame([], $silent);
        static::assertNotSame([], $asking);
        static::assertNotSame([], $onTheSessionAlone);
    }

    #[Test]
    public function aPageThatAsksForARecentProofSendsASessionThatProvedNothingToTheLogin(): void
    {
        // Given
        $this->signIn(self::user('alice'), self::currentSecond()->modify('-1 hour'));

        // When
        $served = [];
        foreach (self::pagesOfTheAccount() as $name => $page) {
            if (! is_a($page[2], AsksForARecentProofInterface::class, true)) {
                continue;
            }
            $this->browser->request($page[0], $page[1]);
            $response = $this->browser->getResponse();
            if (! self::isTheLogin($response)) {
                $served[] = sprintf('%s (%s %s): %d', $name, $page[0], $page[1], $response->getStatusCode());
            }
        }

        // Then
        static::assertSame([], $served);
    }

    #[Test]
    public function aPageReachedOnTheSessionAloneSendsNobodyToTheLogin(): void
    {
        // Given
        $this->signIn(self::user('alice'), self::currentSecond()->modify('-1 hour'));

        // When
        $sentToTheLogin = [];
        foreach (self::pagesOfTheAccount() as $name => $page) {
            if (! is_a($page[2], ReachedOnTheSessionAloneInterface::class, true)) {
                continue;
            }
            $this->browser->request($page[0], $page[1]);
            if (self::isTheLogin($this->browser->getResponse())) {
                $sentToTheLogin[] = sprintf('%s (%s %s)', $name, $page[0], $page[1]);
            }
        }

        // Then
        static::assertSame([], $sentToTheLogin);
    }

    #[Test]
    public function aPageThatAsksRefusesABrowserWithNoSessionRatherThanSendingItToTheLogin(): void
    {
        // When
        $answered = [];
        foreach (self::pagesOfTheAccount() as $name => $page) {
            if (! is_a($page[2], AsksForARecentProofInterface::class, true)) {
                continue;
            }
            $this->browser->request($page[0], $page[1]);
            $status = $this->browser->getResponse()->getStatusCode();
            if ($status !== Response::HTTP_UNAUTHORIZED) {
                $answered[] = sprintf('%s (%s %s): %d', $name, $page[0], $page[1], $status);
            }
        }

        // Then
        static::assertSame([], $answered);
    }

    #[Test]
    public function aPageThatAsksIsRememberedSoTheBrowserComesBackToItOnceTheProofIsGiven(): void
    {
        // Given
        $this->signIn(self::user('alice'), self::currentSecond()->modify('-1 hour'));

        // When
        $this->browser->request('POST', '/account/passkeys');

        // Then
        static::assertTrue(self::isTheLogin($this->browser->getResponse()));
        static::assertSame(
            [
                'route' => 'beffroi_interaction_account_passkeys',
                'parameters' => [],
                'step_up' => null,
            ],
            $this->browser->getRequest()->getSession()->get(LoginTarget::SESSION_KEY),
        );
    }

    #[Test]
    public function aPageThatAsksForgetsTheLoginItWasWaitingForOnceTheProofHolds(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice, self::currentSecond()->modify('-1 hour'));
        $this->browser->request('GET', '/account/passkeys');
        static::assertTrue(self::isTheLogin($this->browser->getResponse()));

        // When
        $this->signIn($alice);
        $this->browser->request('GET', '/account/passkeys');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertNull($this->browser->getRequest()->getSession()->get(LoginTarget::SESSION_KEY));
    }

    #[Test]
    public function aPasskeyIsNotRevokedOnASessionThatProvedNothingRecently(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $token = self::string(
            $this->passkeysPage()
                ->filter('tr[data-passkey="' . $passkey->id . '"] form[data-passkey="revoke"] input[name="_token"]')
                ->attr('value'),
        );
        self::forgetEvents();
        self::mockTime(self::currentSecond()->add(new DateInterval(RecentLogin::WITHIN))->modify('+1 second'));

        // When
        $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/revoke', [
            '_token' => $token,
        ]);

        // Then
        static::assertTrue(self::isTheLogin($this->browser->getResponse()));
        static::assertFalse(self::passkeyOf($alice, $device)->isRevoked());
        static::assertSame([], self::events(CredentialRevoked::class));
    }

    #[Test]
    public function aSessionIsStillEndedOnASessionThatProvedNothingRecently(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice, self::currentSecond()->modify('-1 hour'));
        $other = self::session($alice, self::currentSecond()->modify('-2 hours'));
        $token = self::string(
            $this->browser
                ->request('GET', '/account/sessions')
                ->filter('tr[data-session="' . $other->id . '"] input[name="_token"]')
                ->attr('value'),
        );

        // When
        $this->browser->request('POST', '/account/sessions/' . $other->id . '/revoke', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(Response::HTTP_SEE_OTHER, $this->browser->getResponse()->getStatusCode());
        $reread = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
            ->find($other->id) ?? static::fail('The session is gone.');
        static::assertTrue($reread->hasEnded());
        static::assertSame(SessionEnd::User, $reread->endedBy);
    }

    /**
     * @return iterable<string, array{string, string, class-string}>
     */
    private static function pagesOfTheAccount(): iterable
    {
        foreach (self::service('router', RouterInterface::class)->getRouteCollection() as $name => $route) {
            if (! str_starts_with(self::string($name), AccountAccess::ROUTE_PREFIX)) {
                continue;
            }
            $controller = self::string($route->getDefault('_controller'));
            static::assertTrue(class_exists($controller), sprintf('The route "%s" names no class.', self::string($name)));
            $methods = $route->getMethods();

            yield self::string($name) => [$methods === [] ? 'GET' : $methods[0], self::pathOf($route), $controller];
        }
    }

    private static function pathOf(Route $route): string
    {
        $path = $route->getPath();
        foreach ($route->compile()->getPathVariables() as $variable) {
            $path = str_replace(sprintf('{%s}', self::string($variable)), Uuid::v7()->toRfc4122(), $path);
        }

        return $path;
    }

    private static function isTheLogin(Response $response): bool
    {
        return $response->getStatusCode() === Response::HTTP_FOUND && str_ends_with(self::string($response->headers->get('Location')), '/login');
    }
}
