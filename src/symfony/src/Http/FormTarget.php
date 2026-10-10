<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Oidc\Domain\Client\RedirectUri;
use function explode;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function preg_split;
use function strtolower;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use function trim;

/**
 * Where a form of a page of the interaction plane may send the browser (CSP Level 3 §6.1, §6.3.2): the URI
 * a client registered, which is where a page that completes an authorization request or a logout request
 * sends it.
 *
 * A browser checks "form-action" over the whole redirect chain of a submission and not over the URL the
 * form names: a login page whose policy says "form-action 'self'" posts the password to this provider,
 * follows the redirection that answers it, and refuses the next one, which is the one carrying the code to
 * the client. Nothing reaches the client, the browser stays on the page it posted from and the interaction
 * is spent, so a page that may answer a client names the origin of that client.
 *
 * A deployment cannot name it: a redirection URI belongs to a client, a client may register itself
 * (RFC 7591), and which one is asking is read from the request the page is resuming. So the page names it
 * here and the directive of the policy the answer carries is completed with it, whichever policy that is:
 * the floor of InteractionPages, which restricts no submission and comes out as it went in, or the one an
 * application writes for its pages (apps/op config/packages/nelmio_security.yaml). A policy naming no
 * "form-action" allows every submission and is left alone, the directive falling back to no other.
 *
 * It is named where the page that will carry it is built, and read where the answer leaves, as the name of
 * an exchange is (FapiInteractionId).
 */
final readonly class FormTarget
{
    /**
     * After the policy of the application is written, which is the one to complete. The pages of this plane
     * leave here with the floor of the plane, an application gives way to its own by recognising that floor
     * (apps/op App\Http\DeploymentPolicyPrevails), and a floor completed before that moment is another
     * value it would no longer recognise.
     */
    public const int AFTER_THE_POLICY_IS_WRITTEN = -32;

    private const string DIRECTIVE = 'form-action';

    /**
     * What a browser refuses to combine with a source: "'none'" is a source list on its own (CSP Level 3
     * §2.2.1), so a policy that refuses every submission gives way to the origins the page must reach.
     */
    private const string NO_SOURCE = "'none'";

    /**
     * The two policies an answer may carry, the enforced one and the one that only reports: a report of a
     * submission the provider makes on purpose says nothing to anybody.
     */
    private const array HEADERS = ['Content-Security-Policy', 'Content-Security-Policy-Report-Only'];

    /**
     * Where the origins of a page wait between the controller that names them and the answer that carries
     * them.
     */
    private const string ATTRIBUTE = '_beffroi_form_targets';

    /**
     * Named by a page that may send the browser to this client, once per client it may answer.
     */
    public function mayEndAt(Request $request, RedirectUri $uri): void
    {
        $origins = self::named($request);
        if (in_array($uri->origin, $origins, true)) {
            return;
        }
        $origins[] = $uri->origin;
        $request->attributes->set(self::ATTRIBUTE, $origins);
    }

    #[AsEventListener(event: ResponseEvent::class, priority: self::AFTER_THE_POLICY_IS_WRITTEN)]
    public function onKernelResponse(ResponseEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }
        $origins = self::named($event->getRequest());
        if ($origins === []) {
            return;
        }
        $headers = $event->getResponse()->headers;
        foreach (self::HEADERS as $header) {
            $policies = $headers->all($header);
            if ($policies === []) {
                continue;
            }
            $headers->remove($header);
            foreach ($policies as $policy) {
                $headers->set($header, self::completed((string) $policy, $origins), false);
            }
        }
    }

    /**
     * The same policy with the origins named in its "form-action", and the same policy when it names no
     * such directive.
     *
     * @param non-empty-list<string> $origins
     */
    private static function completed(string $policy, array $origins): string
    {
        $directives = [];
        $completed = false;
        foreach (explode(';', $policy) as $directive) {
            $directive = trim($directive);
            if ($directive === '') {
                continue;
            }
            $written = preg_split('/\s+/', $directive);
            if ($written === false || strtolower($written[0]) !== self::DIRECTIVE) {
                $directives[] = $directive;

                continue;
            }
            $directives[] = implode(' ', self::sourcesOf($written, $origins));
            $completed = true;
        }

        return $completed ? implode('; ', $directives) : $policy;
    }

    /**
     * The directive and its sources, with the origins the page named added to them.
     *
     * @param non-empty-list<string> $written  the name of the directive and the sources it carries
     * @param non-empty-list<string> $origins
     *
     * @return non-empty-list<string>
     */
    private static function sourcesOf(array $written, array $origins): array
    {
        $sources = [$written[0]];
        foreach ($written as $index => $source) {
            if ($index !== 0 && $source !== self::NO_SOURCE) {
                $sources[] = $source;
            }
        }
        foreach ($origins as $origin) {
            if (! in_array($origin, $sources, true)) {
                $sources[] = $origin;
            }
        }

        return $sources;
    }

    /**
     * @return list<string>
     */
    private static function named(Request $request): array
    {
        $origins = $request->attributes->get(self::ATTRIBUTE);
        if (! is_array($origins)) {
            return [];
        }
        $named = [];
        foreach ($origins as $origin) {
            if (is_string($origin)) {
                $named[] = $origin;
            }
        }

        return $named;
    }
}
