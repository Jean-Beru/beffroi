<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use function array_find;
use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;

/**
 * A login the firewall refused, announced as AuthenticationFailed (architecture §3.4, §3.5). Only the
 * routes of the logins wired here are listened to, and what a refusal of one of them means is that
 * login's to read: this knows no login, and a login added to the firewall is a class tagged and nothing
 * edited here.
 */
final readonly class LoginFailureListener
{
    /**
     * @param iterable<AnnouncesItsRefusalInterface> $logins the logins whose refusals this announces;
     *                                                       one that announces its own is not among them
     */
    public function __construct(
        private TenantProvider $tenants,
        private RequestContextFactory $contexts,
        private EventDispatcherInterface $events,
        private iterable $logins,
    ) {
    }

    #[AsEventListener]
    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $request = $event->getRequest();
        $route = $request->attributes->getString('_route');
        $login = array_find(
            [...$this->logins],
            static fn (AnnouncesItsRefusalInterface $candidate): bool => $candidate->route() === $route,
        );
        $failure = $login?->refusal($event->getException(), $event->getPassport());
        if ($failure === null) {
            return;
        }
        $context = $this->contexts->fromRequest($request);
        $this->events->dispatch(new AuthenticationFailed(
            $context->receivedAt,
            $this->tenants->provide(),
            $context,
            $failure->method,
            $failure->reason,
            $failure->identifier,
            $failure->user,
        ));
    }
}
