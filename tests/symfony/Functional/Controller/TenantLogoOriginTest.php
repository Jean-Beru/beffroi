<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\ImageSource;
use App\Http\InteractionPages;
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
 * CSP Level 3 §6.1
 */
final class TenantLogoOriginTest extends BrowserTestCase
{
    private const string WITH_A_LOGO_ELSEWHERE = 'test_tenant_logo';

    private const string DEPLOYMENT_POLICY = "default-src 'none'; img-src 'self'; frame-ancestors 'none'";

    private const string POLICY_WITH_THE_LOGO = "default-src 'none'; img-src 'self' https://brand.test; frame-ancestors 'none'";

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
            // Stands in for the policy an application writes: after the controller, before "img-src" is completed.
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
     * OIDC Registration §2
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
