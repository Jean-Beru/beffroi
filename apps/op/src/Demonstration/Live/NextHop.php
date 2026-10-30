<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

use App\Demonstration\Trace\FlowTrace;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;

/**
 * The next hop of a run the demonstration takes itself (issue #462), read from the picture and from what
 * the trace already holds: the first hop of the picture that is still to be taken.
 *
 * A hop no driven hop claims is skipped: it is a hop a browser takes, and the run goes on to what the
 * client does next, which for a device flow is to poll and be told to wait. A hop the picture says
 * repeats is taken again while the answer to it says the flow is not ready; a hop that does not repeat
 * is taken once, failed or not, so a flow that broke is read on the screen rather than tried for ever.
 */
final readonly class NextHop
{
    /**
     * The tag the wiring puts on every hop the demonstration takes itself (config/packages/demonstration.yaml).
     */
    public const string HOPS = 'app.demonstration.hop';

    /**
     * @param iterable<DrivenHopInterface> $hops one class per hop the demonstration takes itself,
     *                                           collected by the tag the wiring puts on them
     */
    public function __construct(
        #[AutowireIterator(self::HOPS)]
        private iterable $hops,
        private ServedGrantsInterface $served,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function of(FlowPicture $picture, FlowTrace $trace): ?DrivenHopInterface
    {
        foreach ($picture->hops as $hop) {
            $driven = $this->driving($picture, $hop);
            if ($driven === null || $this->taken($driven, $hop, $trace)) {
                continue;
            }

            return $driven;
        }

        return null;
    }

    /**
     * Whether a page of the demonstration can open this flow at all: its first hop is one the
     * demonstration takes itself. A flow that opens in a browser navigating away is replayed and not
     * driven.
     *
     * @throws InvalidArgumentException
     */
    public function opens(FlowPicture $picture): bool
    {
        return $this->driving($picture, $picture->hops[0]) !== null;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function driving(FlowPicture $picture, Hop $hop): ?DrivenHopInterface
    {
        foreach ($this->hops as $driven) {
            if ($driven->hops()[0] !== $hop->name) {
                continue;
            }
            foreach ($driven->flows($this->served) as $flow) {
                if ($flow->equals($picture->grantType)) {
                    return $driven;
                }
            }
        }

        return null;
    }

    private function taken(DrivenHopInterface $driven, Hop $hop, FlowTrace $trace): bool
    {
        $answer = $driven->hops()[1];
        if (! $trace->drew($answer)) {
            return false;
        }
        if (! $hop->repeats) {
            return true;
        }
        foreach ($trace->hops as $traced) {
            if ($traced->hop === $answer) {
                $last = $traced;
            }
        }

        return isset($last) && ! $last->failed;
    }
}
