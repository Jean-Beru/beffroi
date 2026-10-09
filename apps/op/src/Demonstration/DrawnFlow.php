<?php

declare(strict_types=1);

namespace App\Demonstration;

use function array_map;
use App\Demonstration\Trace\FlowTrace;
use App\Demonstration\Trace\Payload;
use App\Demonstration\Trace\TracedHop;
use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Domain\Flow\Hop;

/**
 * A flow and what it exchanged, as one page reads it (issue #462): the actors of the picture, the hops
 * the picture plans, and the hops that really happened, each with the payload that travelled and the
 * compact JWTs that payload carried.
 *
 * The plan and the trace are joined here and nowhere else: a hop that happened is drawn between the
 * actors its picture names, and a hop that did not happen is drawn as a hop of the plan nobody took.
 * A trace that holds a hop no picture plans is drawn as nothing, because a drawing has nowhere to put
 * it; that is a provider and a demonstration that disagree, and the page is not the place to hide it.
 */
final readonly class DrawnFlow
{
    /**
     * The flow, the client whose trace it is, the actors of the picture, the plan (one entry per hop of
     * the picture, with how many times it was taken) and the hops that happened, in the order they
     * happened, each with its payload, the indented reading of it and the compact JWTs it carried.
     *
     * @return array<string, mixed>
     */
    public function of(FlowPicture $picture, ?FlowTrace $trace): array
    {
        return [
            'flow' => $picture->grantType->value,
            'client' => $trace?->clientId,
            'actors' => array_map(static fn (Actor $actor): string => $actor->value, $picture->actors()),
            'plan' => array_map(static fn (Hop $hop): array => [
                'name' => $hop->name,
                'from' => $hop->from->value,
                'to' => $hop->to->value,
                'specification' => $hop->specification,
                'repeats' => $hop->repeats,
                'taken' => $trace?->times($hop->name) ?? 0,
            ], $picture->hops),
            'hops' => $this->hops($picture, $trace),
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function hops(FlowPicture $picture, ?FlowTrace $trace): array
    {
        if ($trace === null) {
            return [];
        }
        $hops = [];
        foreach ($trace->hops as $traced) {
            $planned = self::planned($picture, $traced->hop);
            if ($planned === null) {
                continue;
            }
            $hops[] = self::drawn($traced, $planned);
        }

        return $hops;
    }

    /**
     * @return array<string, mixed>
     */
    private static function drawn(TracedHop $traced, Hop $planned): array
    {
        $payload = Payload::of($traced->payload);

        return [
            'name' => $traced->hop,
            'from' => $planned->from->value,
            'to' => $planned->to->value,
            'specification' => $planned->specification,
            'at' => $traced->at->format('H:i:s.v'),
            'method' => $traced->method,
            'url' => $traced->url,
            'status' => $traced->status,
            'failed' => $traced->failed,
            'reason' => $traced->reason,
            'raw' => $traced->payload,
            'indented' => $payload->indented,
            'jwts' => self::jwts($payload),
        ];
    }

    /**
     * @return list<array{name: string, raw: string, header: string, claims: string|null}>
     */
    private static function jwts(Payload $payload): array
    {
        $jwts = [];
        foreach ($payload->jwts as $name => $jwt) {
            $jwts[] = [
                'name' => $name,
                'raw' => $jwt->raw,
                'header' => $jwt->header,
                'claims' => $jwt->claims,
            ];
        }

        return $jwts;
    }

    private static function planned(FlowPicture $picture, string $name): ?Hop
    {
        foreach ($picture->hops as $hop) {
            if ($hop->name === $name) {
                return $hop;
            }
        }

        return null;
    }
}
