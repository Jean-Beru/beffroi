<?php

declare(strict_types=1);

namespace App\Http;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * Where a page of the interaction plane may load an image from (CSP Level 3 §6.1): the host a client
 * named for its logo, which the consent page shows (ConsentPage), and the one a tenant named for its own,
 * which every page that reads the tenant may show (Twig\TenantExtension, issue #926).
 *
 * A deployment names its own origin and cannot name those: the logo of a client is served by a host that
 * client registered, and a client may register itself (RFC 7591); the logo of a tenant is a value of the
 * configuration of the provider, an environment variable of the image, which a policy written in a file of
 * the application would have to repeat by hand. So the page names the origins of the images it may load
 * and the "img-src" of the policy the answer carries is completed with them, whichever policy that is
 * (PolicyCompletion). What the page loads stays bounded by that: the origin of each of those images and
 * no other, so nothing a client registers makes a page of this provider load anything else.
 *
 * A policy that names "default-src" and no "img-src" refuses an image at the fallback, so the directive
 * is written out of that one: a deployment whose "default-src 'none'" never mentioned an image still
 * serves the ones the page shows, and still nothing more.
 */
final readonly class ImageSource
{
    /**
     * Where the origins of a page wait between the controller that names them and the answer that carries
     * them.
     */
    private const string ATTRIBUTE = '_beffroi_image_sources';

    private const string DIRECTIVE = 'img-src';

    /**
     * CSP Level 3 §6.1: what a fetch directive a policy leaves out answers with.
     */
    private const string FALLBACK = 'default-src';

    private PolicyCompletion $completion;

    public function __construct()
    {
        $this->completion = new PolicyCompletion(self::ATTRIBUTE, self::DIRECTIVE, self::FALLBACK);
    }

    /**
     * Named by a page that shows images served from these origins; a page that shows none names none and
     * the policy of the answer is the one the deployment wrote.
     *
     * @param list<string> $origins
     */
    public function mayLoadFrom(Request $request, array $origins): void
    {
        foreach ($origins as $origin) {
            $this->completion->mayReach($request, $origin);
        }
    }

    #[AsEventListener(event: ResponseEvent::class, priority: PolicyCompletion::AFTER_THE_POLICY_IS_WRITTEN)]
    public function onKernelResponse(ResponseEvent $event): void
    {
        $this->completion->complete($event);
    }
}
