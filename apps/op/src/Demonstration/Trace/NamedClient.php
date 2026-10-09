<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use function is_string;
use function rawurldecode;
use Symfony\Component\HttpFoundation\Request;

/**
 * The client a call to this provider names (RFC 6749 §2.3.1, §3.2.1): the "client_id" it carries, or the
 * user half of the credentials it authenticated with, which a client registered for
 * "client_secret_basic" sends form-urlencoded. Read the same way at every endpoint that names a client,
 * so that no endpoint of the demonstration reads it its own way.
 */
final readonly class NamedClient
{
    public const string PARAMETER = 'client_id';

    public static function of(Request $request): ?string
    {
        $user = $request->getUser();
        if (is_string($user) && $user !== '') {
            return rawurldecode($user);
        }
        foreach ([$request->request, $request->query] as $parameters) {
            $clientId = $parameters->get(self::PARAMETER);
            if (is_string($clientId) && $clientId !== '') {
                return $clientId;
            }
        }

        return null;
    }
}
