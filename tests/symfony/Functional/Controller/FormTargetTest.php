<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\InteractionPages;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Closure;
use DateTimeImmutable;
use function intdiv;
use PHPUnit\Framework\Attributes\Test;
use Psr\Container\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Uid\Uuid;

/**
 * CSP Level 3 §6.1, §6.3.2
 */
final class FormTargetTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    private const string DEPLOYMENT_POLICY = "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'";

    private const string CLIENT_ID = 'oidc-demo';

    private const string REDIRECT_URI = 'https://demo.test/login/check';

    private const string CLIENT_ORIGIN = 'https://demo.test';

    private const string CONSENT_CLIENT_ID = 'consent-app';

    private const string CONSENT_REDIRECT_URI = 'https://consent.test/callback';

    private const string CONSENT_CLIENT_ORIGIN = 'https://consent.test';

    private const string CONSENT_LOGO_ORIGIN = 'https://cdn.consent.test';

    /**
     * beffroi/saml S-36
     */
    private const string SERVICE_PROVIDER_ORIGIN = 'https://sp.example.org';

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $dispatcher = $container->get('event_dispatcher');
            static::assertInstanceOf(EventDispatcherInterface::class, $dispatcher);
            // Writes the policy as an application does: before the directive of a page is completed (FormTarget),
            // and only on the pages the provider computes no policy for, as App\Http\DeploymentPolicyPrevails
            // leaves them.
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
    public function theLoginPageOfAnAuthorizationRequestNamesTheOriginOfTheClient(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);
        $interaction = $this->authorizeTheClient();

        // When
        $this->loginPage($interaction);

        // Then
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * Architecture §5.4
     */
    #[Test]
    public function theCodePageOfAnAuthorizationRequestNamesTheOriginOfTheClient(): void
    {
        // Given
        $this->userWithTotp('alice', self::PASSWORD);
        $interaction = $this->authorizeTheClient();
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;
        $this->browser->submit($form);

        // When
        $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * RP-Initiated Logout §2
     */
    #[Test]
    public function theLogoutConfirmationNamesWhereTheClientAskedToBeSentBack(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/logout', [
            'client_id' => self::CLIENT_ID,
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN), $this->policyOfTheAnswer());
    }

    #[Test]
    public function theConsentPageNamesTheClientItMayAnswerAndTheHostOfTheLogoItShows(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $interaction = $this->authorize([
            'client_id' => self::CONSENT_CLIENT_ID,
            'redirect_uri' => self::CONSENT_REDIRECT_URI,
        ]);

        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            "default-src 'none'; script-src 'self'; img-src 'self' "
            . self::CONSENT_LOGO_ORIGIN
            . "; form-action 'self' "
            . self::CONSENT_CLIENT_ORIGIN
            . "; frame-ancestors 'none'",
            $this->policyOfTheAnswer(),
        );
    }

    /**
     * beffroi/saml S-36
     */
    #[Test]
    public function theLogoutConfirmationNamesTheSingleLogoutServicesOfTheSession(): void
    {
        // Given
        $this->signedInAtTheServiceProvider();

        // When
        $this->browser->request('GET', '/logout', [
            'client_id' => self::CLIENT_ID,
            'post_logout_redirect_uri' => 'https://demo.test/',
            'state' => 'after-logout',
        ]);

        // Then
        static::assertSame(self::policyNaming(self::CLIENT_ORIGIN . ' ' . self::SERVICE_PROVIDER_ORIGIN), $this->policyOfTheAnswer());
    }

    /**
     * beffroi/saml S-36
     */
    #[Test]
    public function theSessionsPageNamesTheSingleLogoutServicesOfTheSessionOfTheBrowser(): void
    {
        // Given
        $this->signedInAtTheServiceProvider();

        // When
        $this->browser->request('GET', '/account/sessions');

        // Then
        static::assertSame(self::policyNaming(self::SERVICE_PROVIDER_ORIGIN), $this->policyOfTheAnswer());
    }

    #[Test]
    public function aPageThatAnswersNoClientNamesNoOrigin(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/account');

        // Then
        static::assertSame(self::DEPLOYMENT_POLICY, $this->policyOfTheAnswer());
    }

    /**
     * beffroi/saml S-26, S-30
     */
    private function signedInAtTheServiceProvider(): AuthenticationSession
    {
        $session = $this->signIn(self::user('alice'));
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedServiceProviderMetadata(
                Uuid::v7(),
                self::tenant(),
                ServiceProviderDocuments::SIGNED,
                ServiceProviderDocuments::exampleOrgWithSingleLogout([[
                    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    ServiceProviderDocuments::SIGNED . '/slo',
                    null,
                ]]),
                null,
                self::currentSecond(),
            ));
        self::service('test.beffroi.saml_session_participants', SessionParticipationRepositoryInterface::class)
            ->record(new SessionParticipation(Uuid::v7(), self::tenant(), $session, ServiceProviderDocuments::SIGNED, self::currentSecond()));

        return $session;
    }

    private function authorizeTheClient(): string
    {
        return $this->authorize([
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
        ]);
    }

    private function userWithTotp(string $username, string $password): User
    {
        $user = self::userWithPassword($username, $password);
        $secret = Totps::secret();
        $anHourAgo = new DateTimeImmutable('-1 hour');
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(
                new TotpCredential(
                    Uuid::v7(),
                    $user,
                    self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $secret->bytes),
                    Totps::credential($user, new FakePasswordHasher())->backupCodes,
                    intdiv($anHourAgo->getTimestamp(), TotpCredential::PERIOD),
                    $anHourAgo,
                ),
            );

        return $user;
    }

    private static function policyNaming(string $origin): string
    {
        return "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self' " . $origin . "; frame-ancestors 'none'";
    }

    private function policyOfTheAnswer(): string
    {
        $policy = $this->browser->getResponse()->headers->get('Content-Security-Policy');
        static::assertIsString($policy);

        return $policy;
    }
}
