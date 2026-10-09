<?php

declare(strict_types=1);

namespace App\Demonstration\Live\Hop;

use App\Demonstration\Live\DemonstrationClient;
use App\Demonstration\Live\DrivenCall;
use App\Demonstration\Live\DrivenHopInterface;
use App\Demonstration\Live\Holdings;
use App\Demonstration\Trace\FlowTrace;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedThroughABackchannel;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * CIBA Core §7: the client names the user it is asking for, and is told the request was taken. What a
 * "login_hint" names is this provider's to decide (§7.1, §15), so the demonstration names the user the
 * way the lab is configured to and reads nothing into it.
 */
final readonly class AskTheBackchannelAuthenticationEndpoint implements DrivenHopInterface
{
    /**
     * What the user reads on the device this provider reaches them on (§7.1): the same message every
     * run, so that what is being allowed is recognisable on the screen beside the picture.
     */
    public const string BINDING_MESSAGE = 'The demonstration';

    public function flows(ServedGrantsInterface $served): array
    {
        return $served->askingTheUserThroughABackchannel();
    }

    public function call(FlowTrace $trace, ProviderEndpoints $endpoints, DemonstrationClient $client): ?DrivenCall
    {
        if ($client->loginHint === null) {
            return null;
        }

        return new DrivenCall(Request::METHOD_POST, $endpoints->backchannelAuthentication, [
            'scope' => $client->scope,
            'login_hint' => $client->loginHint,
            'binding_message' => self::BINDING_MESSAGE,
        ]);
    }

    public function hops(): array
    {
        return [
            TheUserIsAskedThroughABackchannel::BACKCHANNEL_AUTHENTICATION_REQUEST,
            TheUserIsAskedThroughABackchannel::BACKCHANNEL_AUTHENTICATION_RESPONSE,
        ];
    }

    public function keeps(array $answer): array
    {
        return Holdings::kept($answer, [Holdings::AUTH_REQUEST_ID]);
    }
}
