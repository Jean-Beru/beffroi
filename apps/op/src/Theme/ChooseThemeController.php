<?php

declare(strict_types=1);

namespace App\Theme;

use function preg_match;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The theme a visitor asked for, kept for their browser (issue #447): a route of this application and
 * not of the provider, the look of the pages being the decision of the application (architecture §5.2). Its
 * name carries the interaction plane (issue #988): it is a form only a browser posts, which a process that
 * serves the protocol alone answers with a 404, as it answers every page meant for a browser.
 *
 * It answers a form and no script: the choice is a POST that comes back to the page it was made on, so
 * the pages work for a browser that runs nothing, and a theme is never a path (architecture §5.7, the
 * rule the language of the pages already follows).
 */
#[AsController]
final readonly class ChooseThemeController
{
    public const string ROUTE = 'beffroi_interaction_theme';

    public function __construct(
        private ChosenTheme $chosen,
    ) {
    }

    #[Route('/theme', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $response = new RedirectResponse(self::backTo($request));
        $response->headers->setCookie($this->chosen->cookie($request, Theme::ofChoice($request->request->getString('theme'))));

        return $response;
    }

    /**
     * The page the choice was made on, which the form carries, and the root of the application for
     * anything that is not a path of this origin: a choice of colour does not send a browser elsewhere.
     */
    private static function backTo(Request $request): string
    {
        $target = $request->request->getString('target');

        return preg_match('#^/(?![/\\\\])[^\s\\\\]*$#D', $target) === 1 ? $target : '/';
    }
}
