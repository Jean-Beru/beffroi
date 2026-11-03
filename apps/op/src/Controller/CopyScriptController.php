<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\ProviderScript;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The script a page of the account runs to put what it shows into the clipboard of whoever is reading it
 * (Clipboard API §3, architecture §5.2): the backup codes of a second factor, shown once and copied in
 * one click rather than by hand.
 */
#[AsController]
final readonly class CopyScriptController
{
    public const string ROUTE = 'beffroi_interaction_copy_script';

    public const string FILE = 'copy.js';

    public function __construct(
        private ProviderScript $scripts,
    ) {
    }

    #[Route('/copy.js', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        return $this->scripts->serve($request, self::FILE);
    }
}
