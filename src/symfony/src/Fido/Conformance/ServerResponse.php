<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Fido\Conformance;

use function is_array;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * The envelope every answer of the FIDO2 server API wears (FIDO Conformance Tools, "ServerResponse"): a
 * status of "ok" or "failed" and an error message, empty on success, next to what the endpoint returns.
 */
final readonly class ServerResponse
{
    /**
     * @param array<string, mixed> $body
     */
    public static function ok(array $body = []): JsonResponse
    {
        return new JsonResponse([
            'status' => 'ok',
            'errorMessage' => '',
            ...$body,
        ]);
    }

    /**
     * The options of a ceremony, as the ceremonies serialise them for a browser, in the envelope.
     */
    public static function options(string $optionsJson): JsonResponse
    {
        $options = json_decode($optionsJson, true, 16, JSON_THROW_ON_ERROR);
        $members = [];
        foreach (is_array($options) ? $options : [] as $name => $value) {
            $members[(string) $name] = $value;
        }

        return self::ok($members);
    }

    public static function failed(string $errorMessage): JsonResponse
    {
        return new JsonResponse([
            'status' => 'failed',
            'errorMessage' => $errorMessage,
        ], Response::HTTP_BAD_REQUEST);
    }
}
