<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #447, architecture §6: the form of the theme comes back to the page it was sent from when that is
 * a path of this origin, and to the root of the application otherwise, a choice of colour sending a browser
 * nowhere else (App\Controller\ChooseThemeController).
 */
final class ThemeChoiceTest extends BrowserTestCase
{
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
}
