<?php

declare(strict_types=1);

namespace App\Http;

use function get_current_user;
use function gethostname;
use Beffroi\Core\Domain\Session\RequestContext;
use function is_string;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;

/**
 * The RequestContext of the core (architecture §3.5): for an HTTP request, or for a process that is no
 * request, the console naming its command and the user of the shell, the scheduler naming its schedule,
 * in the place of a user agent and with no address. Nothing is enriched here.
 */
final readonly class RequestContextFactory
{
    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    public function fromRequest(Request $request): RequestContext
    {
        return new RequestContext($this->clock->now(), $request->getClientIp(), $request->headers->get('User-Agent'));
    }

    public function fromConsole(string $command): RequestContext
    {
        return new RequestContext($this->clock->now(), null, sprintf('beffroi-console/%s (%s@%s)', $command, self::shellUser(), self::host()));
    }

    public function fromSchedule(string $schedule): RequestContext
    {
        return new RequestContext($this->clock->now(), null, sprintf('beffroi-scheduler/%s (%s)', $schedule, self::host()));
    }

    /**
     * Who typed the command: the user behind a sudo first, then the user of the shell, then the owner of
     * the script as the last resort.
     */
    private static function shellUser(): string
    {
        foreach (['SUDO_USER', 'USER', 'USERNAME'] as $variable) {
            $user = $_SERVER[$variable] ?? null;
            if (is_string($user) && $user !== '') {
                return $user;
            }
        }

        return get_current_user();
    }

    private static function host(): string
    {
        $host = gethostname();

        return $host === false ? 'unknown-host' : $host;
    }
}
