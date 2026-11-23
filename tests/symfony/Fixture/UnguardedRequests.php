<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Http\OutboundGuardInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * This kernel opens no socket: a request a test sends goes to the MockHttpClient it hands, under a name of "example"
 * that no resolver knows, which the guard of a deployment would refuse before the mock saw it.
 */
final readonly class UnguardedRequests implements OutboundGuardInterface
{
    public function guard(HttpClientInterface $client): HttpClientInterface
    {
        return $client;
    }
}
