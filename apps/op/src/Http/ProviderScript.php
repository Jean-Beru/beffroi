<?php

declare(strict_types=1);

namespace App\Http;

use function dirname;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * A script of the provider, served by the provider itself under the path of its pages (architecture §5.2): no
 * asset pipeline, no CDN, and no change to the Content-Security-Policy of an application that only allows
 * its own origin. Cacheable, and carrying nothing of a user or of a tenant: what a page has to tell a
 * script, it tells it in the attributes of the element the script reads.
 */
final readonly class ProviderScript
{
    /**
     * An hour: a script that changes is a deployment, and the digest is compared before that anyway.
     */
    public const int MAX_AGE = 3600;

    public function serve(Request $request, string $file): Response
    {
        $response = new BinaryFileResponse(
            dirname(__DIR__, 2) . '/scripts/' . $file,
            Response::HTTP_OK,
            [
                'Content-Type' => 'text/javascript; charset=utf-8',
            ],
            false,
        );
        $response->setAutoEtag();
        $response->setPublic();
        $response->setMaxAge(self::MAX_AGE);
        $response->isNotModified($request);

        return $response;
    }
}
