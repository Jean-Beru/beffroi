<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Http\ImageSource;
use Beffroi\Bundle\Http\InteractionPages;
use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Container\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Twig\Environment;

/**
 * Issue #926, CSP Level 3 §6.1: the logo of the tenant is on every page of the plane (_brand.html.twig), and a
 * deployment may serve it from another host than its issuer. So every page that shows it names the origin it is
 * served from in the "img-src" of the policy its deployment writes, the bundle completing that directive once the
 * policy is written (ImageSource), and no deployment names that origin by hand.
 *
 * The tenant of this environment serves its logo from a host of its own (config_test_tenant_logo.yml). The kernel of
 * this suite writes no policy of its own, so the listener below stands in for the one an application writes, as it
 * does in FormTargetTest: every image is served by the provider and no other host.
 */
final class TenantLogoOriginTest extends BrowserTestCase
{
    /**
     * The environment whose tenant serves its logo from another origin than its issuer.
     */
    private const string WITH_A_LOGO_ELSEWHERE = 'test_tenant_logo';

    private const string DEPLOYMENT_POLICY = "default-src 'none'; img-src 'self'; frame-ancestors 'none'";

    /**
     * What the policy of a page that shows the logo becomes: the host of the logo beside this provider.
     */
    private const string POLICY_WITH_THE_LOGO = "default-src 'none'; img-src 'self' https://brand.test; frame-ancestors 'none'";

    /**
     * The client consent is required of, the one declared with a logo of its own (config_test.yml).
     */
    private const string CONSENT_CLIENT_ID = 'consent-app';

    private const string CONSENT_REDIRECT_URI = 'https://consent.test/callback';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::WITH_A_LOGO_ELSEWHERE,
        ];
    }

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $dispatcher = $container->get('event_dispatcher');
            static::assertInstanceOf(EventDispatcherInterface::class, $dispatcher);
            // where the policy of an application is written: after the controller that answered, before the
            // directive of a page is completed, and on the pages the bundle computes no policy for, as
            // App\Http\DeploymentPolicyPrevails leaves them
            $dispatcher->addListener(
                KernelEvents::RESPONSE,
                static function (ResponseEvent $event): void {
                    $response = $event->getResponse();
                    if (! $event->isMainRequest() || $response->isRedirection()) {
                        return;
                    }
                    if ($response->headers->get('Content-Security-Policy') !== InteractionPages::HEADERS['Content-Security-Policy']) {
                        return;
                    }
                    $response->headers->set('Content-Security-Policy', self::DEPLOYMENT_POLICY);
                },
                0,
            );
        };
    }

    /**
     * The page the browser of an authorization request lands on, before anybody signed in.
     */
    #[Test]
    public function theLoginPageMayLoadItFromTheHostThatServesIt(): void
    {
        // Given
        $interaction = $this->interactionOf(self::authorizationParameters());

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::POLICY_WITH_THE_LOGO, $this->policyOfTheAnswer());
    }

    /**
     * The pages a person reads once signed in are pages of the same layout, the logo above them.
     */
    #[Test]
    #[DataProvider('providePagesOfASignedInPerson')]
    public function aPageOfASignedInPersonMayLoadItFromTheHostThatServesIt(string $path): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $this->browser->request('GET', $path);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::POLICY_WITH_THE_LOGO, $this->policyOfTheAnswer());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePagesOfASignedInPerson(): iterable
    {
        yield 'the home of the account' => ['/account'];
        yield 'the page a device code is typed on (RFC 8628 §3.3)' => ['/device'];
    }

    /**
     * An error page is framed by the same layout, so a refusal shows the logo too.
     */
    #[Test]
    public function anErrorPageMayLoadItFromTheHostThatServesIt(): void
    {
        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => 'an-interaction-nobody-began',
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::POLICY_WITH_THE_LOGO, $this->policyOfTheAnswer());
    }

    /**
     * The consent page shows two logos, the one of the client that asks and the one of its tenant, and names the
     * origin of each (OIDC Registration §2).
     */
    #[Test]
    public function theConsentPageMayLoadTheLogoOfTheClientAndTheOneOfTheTenant(): void
    {
        // Given
        $this->signIn(self::user());
        $interaction = $this->interactionOf(self::authorizationParameters(self::CONSENT_CLIENT_ID, [
            'redirect_uri' => self::CONSENT_REDIRECT_URI,
        ]));

        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            "default-src 'none'; img-src 'self' https://cdn.consent.test https://brand.test; frame-ancestors 'none'",
            $this->policyOfTheAnswer(),
        );
    }

    /**
     * A page rendered by a sub-request, the error page of an exception the kernel caught among them, leaves as the
     * answer of the main request, and that answer is the one whose policy is completed: the origin is named for the
     * main request, whichever request the template was rendered for.
     */
    #[Test]
    public function aTemplateRenderedForASubRequestNamesTheOriginForTheAnswerOfTheMainOne(): void
    {
        // Given
        $main = Request::create('https://op.test/account');
        $requests = self::service('request_stack', RequestStack::class);
        $requests->push($main);
        $requests->push($main->duplicate());
        $response = new Response('a page of the interaction plane', Response::HTTP_OK, [
            'Content-Security-Policy' => self::DEPLOYMENT_POLICY,
        ]);

        // When
        self::service('twig', Environment::class)->createTemplate('{{ beffroi_tenant().name }}')->render();
        self::service(ImageSource::class, ImageSource::class)
            ->onKernelResponse(
                new ResponseEvent($this->browser->getKernel(), $main, HttpKernelInterface::MAIN_REQUEST, $response),
            );

        // Then
        static::assertSame(self::POLICY_WITH_THE_LOGO, $response->headers->get('Content-Security-Policy'));
    }

    /**
     * The interaction an authorization request began, read where the browser was sent.
     *
     * @param array<string, string> $parameters
     */
    private function interactionOf(array $parameters): string
    {
        $this->browser->request('GET', '/authorize', $parameters);

        return self::redirectedInteraction($this->browser->getResponse());
    }

    private function policyOfTheAnswer(): string
    {
        $policy = $this->browser->getResponse()->headers->get('Content-Security-Policy');
        static::assertIsString($policy);

        return $policy;
    }
}
