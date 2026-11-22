<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Flow\FlowShapeInterface;
use Beffroi\Oidc\Application\Flow\TheClientActsForItself;
use Beffroi\Oidc\Application\Flow\TheClientAsksForATokenAlone;
use Beffroi\Oidc\Application\Flow\TheProviderIsAskedWhoTheUserIs;
use Beffroi\Oidc\Application\Flow\TheRefreshTokenIsSpent;
use Beffroi\Oidc\Application\Flow\TheResourceServerAsksWhatTheTokenIs;
use Beffroi\Oidc\Application\Flow\TheTokenIsGivenBack;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedOnAnotherDevice;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedThroughABackchannel;
use Beffroi\Oidc\Application\Flow\TheUserIsSentToTheClient;
use Beffroi\Oidc\Application\Flow\WiredFlowPictures;
use Beffroi\Oidc\Port\ServedGrantsInterface;

final readonly class Flows
{
    /**
     * @param list<FlowShapeInterface> $openings
     * @param list<FlowShapeInterface> $closings
     */
    public static function of(ServedGrantsInterface $served, ?array $openings = null, ?array $closings = null): WiredFlowPictures
    {
        return new WiredFlowPictures($served, $openings ?? self::openings(), $closings ?? self::closings());
    }

    /**
     * @return list<FlowShapeInterface>
     */
    public static function openings(): array
    {
        return [
            new TheUserIsSentToTheClient(),
            new TheUserIsAskedOnAnotherDevice(),
            new TheUserIsAskedThroughABackchannel(),
            new TheClientActsForItself(),
            new TheClientAsksForATokenAlone(),
        ];
    }

    /**
     * @return list<FlowShapeInterface>
     */
    public static function closings(): array
    {
        return [
            new TheProviderIsAskedWhoTheUserIs(),
            new TheResourceServerAsksWhatTheTokenIs(),
            new TheRefreshTokenIsSpent(),
            new TheTokenIsGivenBack(),
        ];
    }
}
