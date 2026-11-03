<?php

declare(strict_types=1);

namespace App\Http;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * The Content-Security-Policy of this deployment, on the pages of the interaction plane too
 * (config/packages/nelmio_security.yaml).
 *
 * The provider gives every page of that plane a policy of its own, "frame-ancestors 'none'", which is the
 * refusal to be framed RFC 9700 §4.15 asks for and what a deployment that configures nothing still gets.
 * It is a floor and not a ceiling: the two pages that carry a step of the protocol say so by writing a
 * whole policy of their own (the hash of the script of a form post response, the frames of a front channel
 * logout), and this application says so by configuring one.
 *
 * Nothing merges two policies, and nothing can: two Content-Security-Policy headers on one answer are both
 * enforced and what applies is their intersection, and a policy a page never asked for is what the page
 * would then break on. So one of the two is sent, and on a page where the floor is all the provider had to
 * say, the one this deployment configured is the one that says more: it names "frame-ancestors 'none'"
 * as well, and the script sources, the base URI, the form targets and the plugin sources besides.
 *
 * The floor is dropped and nothing is written in its place: the answer leaves here with no policy at all
 * and the listener of nelmio/security-bundle writes the one of the deployment on it, which it does for
 * every answer that carries none. Hence the priority, which puts this before that listener and before
 * nothing else, and hence the comparison: a page carrying a whole policy of its own carries another value,
 * and another value is left alone.
 *
 * What a page of the plane has to say about its own request is not a policy of its own: it is a directive
 * of this one, completed after it is written (App\Http\PolicyCompletion). The consent page
 * shows the logo of a host a client named and ends at that client, and it is served the policy of this
 * deployment with that host in its "img-src" and that client in its "form-action".
 *
 * A redirection keeps its floor. That listener writes no policy on one, so dropping it there would be
 * dropping it for good, and a redirection of this plane is an answer like any other.
 */
#[AsEventListener(event: ResponseEvent::class, priority: self::BEFORE_THE_POLICY_IS_WRITTEN)]
final readonly class DeploymentPolicyPrevails
{
    /**
     * The listener of nelmio/security-bundle writes the policy on the response event at the priority a
     * subscriber gets when it names none, which is zero.
     */
    public const int BEFORE_THE_POLICY_IS_WRITTEN = 32;

    public const string HEADER = 'Content-Security-Policy';

    public function __invoke(ResponseEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();
        if ($response->isRedirection()) {
            return;
        }

        if ($response->headers->get(self::HEADER) === InteractionPages::HEADERS[self::HEADER]) {
            $response->headers->remove(self::HEADER);
        }
    }
}
