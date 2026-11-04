<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #447, architecture §6: the form of the theme comes back to the page it was sent from when that is
 * a path of this origin, and to the root of the application otherwise, a choice of colour sending a browser
 * nowhere else (App\Theme\ChooseThemeController).
 */
final class ThemeChoiceTest extends BrowserTestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_PLANE'], $_ENV['BEFFROI_PLANE']);
    }

    #[Test]
    public function aChoiceComesBackToThePageItWasMadeOn(): void
    {
        // When
        $this->browser->request('POST', '/theme', ['theme' => 'dark', 'target' => '/account']);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/account', $response->headers->get('Location'));
    }

    #[Test]
    #[DataProvider('provideTargetsThatAreNotAPathOfThisOrigin')]
    public function aTargetThatIsNotAPathOfThisOriginComesBackToTheRoot(string $target): void
    {
        // When
        $this->browser->request('POST', '/theme', ['theme' => 'dark', 'target' => $target]);

        // Then
        static::assertSame('/', $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTargetsThatAreNotAPathOfThisOrigin(): iterable
    {
        yield 'another origin' => ['//elsewhere.test/callback'];
        yield 'a line feed behind a path that would pass' => ["/account\n"];
    }

    /**
     * Issue #988, architecture §5.2: the choice of a theme is a form only a browser posts, so its route carries
     * the interaction plane, and a process that serves the protocol alone answers it with the 404 an unknown
     * path gets, as it answers every page meant for a browser (Plane::ofRoute).
     */
    #[Test]
    #[DataProvider('provideThePlanesOfAProcess')]
    public function aProcessAnswersTheChoiceOfAThemeOnTheInteractionPlaneOnly(string $plane, int $status): void
    {
        // Given
        $_ENV['BEFFROI_PLANE'] = $plane;
        $_SERVER['BEFFROI_PLANE'] = $plane;
        self::ensureKernelShutdown();
        $browser = static::createClient([], ['HTTPS' => 'on']);

        // When
        $browser->request('POST', '/theme', ['theme' => 'dark', 'target' => '/account']);

        // Then
        static::assertSame($status, $browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideThePlanesOfAProcess(): iterable
    {
        yield 'a process of the protocol plane refuses it' => ['protocol', Response::HTTP_NOT_FOUND];
        yield 'a process of the interaction plane serves it' => ['interaction', Response::HTTP_FOUND];
        yield 'a process of every plane serves it' => ['all', Response::HTTP_FOUND];
    }
}
