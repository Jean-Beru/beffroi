<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http\Account;

use App\Http\Account\BreachedPasswordDemand;
use App\Http\InteractionPages;
use App\Http\LoginTarget;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Loader\ClosureLoader;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\Routing\Router;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

/**
 * Architecture §5.2
 */
final class BreachedPasswordDemandTest extends TestCase
{
    private const string NOW = '2026-10-11T12:00:00+00:00';

    private BreachedPasswordDemand $demand;

    private LoginTarget $loginTargets;

    protected function setUp(): void
    {
        $routes = new RouteCollection();
        $routes->add('beffroi_interaction_login', new Route('/login'));
        $routes->add('beffroi_interaction_account', new Route('/account'));
        $routes->add('beffroi_interaction_account_password', new Route('/account/password'));
        $pages = new InteractionPages(
            new Environment(new ArrayLoader()),
            new Router(new ClosureLoader(), static fn (): RouteCollection => $routes, [], new RequestContext()),
        );
        $this->loginTargets = new LoginTarget($pages);
        $this->demand = new BreachedPasswordDemand($this->loginTargets, $pages);
    }

    #[Test]
    public function aLoginByWhoeverHoldsAPasswordThatWasFoundGoesToThePageOfThePassword(): void
    {
        // Given
        $httpSession = $this->aPageWaitingForTheLogin();

        // When
        $response = $this->demand->insteadOfResuming($httpSession, self::aPasswordFoundInABreach());

        // Then
        static::assertNotNull($response);
        static::assertSame('/account/password', $response->headers->get('Location'));
    }

    #[Test]
    public function aLoginByWhoeverHoldsAPasswordNoListFoundIsAskedNothing(): void
    {
        // Given
        $httpSession = $this->aPageWaitingForTheLogin();

        // When / Then
        static::assertNull($this->demand->insteadOfResuming($httpSession, Fixtures::password()));
    }

    #[Test]
    public function aLoginByWhoeverHoldsNoPasswordIsAskedNothing(): void
    {
        // Given
        $httpSession = $this->aPageWaitingForTheLogin();

        // When / Then
        static::assertNull($this->demand->insteadOfResuming($httpSession, null));
    }

    #[Test]
    public function aLoginNoPageOfTheProviderIsWaitingForIsInterruptedByNothing(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());

        // When / Then
        static::assertNull($this->demand->insteadOfResuming($httpSession, self::aPasswordFoundInABreach()));
    }

    #[Test]
    public function thePageSaysWhatIsAskedToABrowserALoginSentThereAndToNoOther(): void
    {
        // Given
        $password = self::aPasswordFoundInABreach();

        // When / Then
        static::assertTrue($this->demand->isMade($this->aPageWaitingForTheLogin(), $password));
        static::assertFalse($this->demand->isMade(new Session(new MockArraySessionStorage()), $password));
    }

    #[Test]
    public function aPasswordReplacedCarriesTheBrowserOnToWhereItWasGoing(): void
    {
        // Given
        $httpSession = $this->aPageWaitingForTheLogin();

        // When
        $response = $this->demand->answered($httpSession);

        // Then
        static::assertNotNull($response);
        static::assertSame('/account', $response->headers->get('Location'));
        static::assertFalse($this->loginTargets->isPending($httpSession));
    }

    #[Test]
    public function aPasswordReplacedWithNoPageWaitingCarriesTheBrowserNowhere(): void
    {
        // Given
        $httpSession = new Session(new MockArraySessionStorage());

        // When / Then
        static::assertNull($this->demand->answered($httpSession));
    }

    private function aPageWaitingForTheLogin(): SessionInterface
    {
        $httpSession = new Session(new MockArraySessionStorage());
        $this->loginTargets->sendToLogin($httpSession, 'beffroi_interaction_account');

        return $httpSession;
    }

    private static function aPasswordFoundInABreach(): PasswordCredential
    {
        $password = Fixtures::password();
        $password->foundInABreach(new DateTimeImmutable(self::NOW));

        return $password;
    }
}
