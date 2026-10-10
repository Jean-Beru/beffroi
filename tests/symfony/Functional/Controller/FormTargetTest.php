<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
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
 * CSP Level 3 §6.1, §6.3.2 on a deployment that says where a form may be submitted: a page of the
 * interaction plane that may send the browser to a client names the origin of that client among the
 * targets of a submission (FormTarget). A browser checks the directive over the whole redirect chain of
 * one, and the last hop of that chain is the answer carried to the client, so a page that names only
 * this provider is a page whose login never reaches the client that asked for it.
 *
 * The kernel of this suite writes no policy of its own: what every page of the plane carries is the floor
 * of the plane, which restricts no submission (architecture §5.2). The listener below stands in for the
 * one an application writes (apps/op config/packages/nelmio_security.yaml), so that what is read here is
 * what a browser reads there.
 */
final class FormTargetTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * What a deployment writes on the pages of this plane, the directive of this test among the ones it
     * names: every form of these pages comes back to the provider, and nothing else may be posted to.
     */
    private const string DEPLOYMENT_POLICY = "default-src 'none'; script-src 'self'; form-action 'self'; frame-ancestors 'none'";

    /**
     * The client of the walks below, and the origin it is answered at.
     */
    private const string CLIENT_ID = 'oidc-demo';

    private const string REDIRECT_URI = 'https://demo.test/login/check';

    private const string CLIENT_ORIGIN = 'https://demo.test';

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $dispatcher = $container->get('event_dispatcher');
            static::assertInstanceOf(EventDispatcherInterface::class, $dispatcher);
            // where the policy of an application is written: after the controller that answered, before
            // the directive of a page is completed with what it may answer (FormTarget), and on the pages
            // the bundle computes no policy for, as App\Http\DeploymentPolicyPrevails leaves them
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
     * The page the browser of an authorization request lands on: the login it asks for ends with the code
     * carried to the client, so the client is named.
     */
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
     * The second step of the same login (architecture §5.4): the code page belongs to the interaction as
     * the login page does, and the code it asks for is what ends the login.
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
     * RP-Initiated Logout §2: a confirmed logout sends the browser where the client asked to be sent
     * back, so the page that asks for the confirmation names it.
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

    /**
     * A page of the account answers no client and sends the browser nowhere: what a deployment wrote is
     * what it carries.
     */
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

    private function authorizeTheClient(): string
    {
        return $this->authorize([
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
        ]);
    }

    /**
     * The user of the walk with a second factor, so that the login takes the code page on its way.
     */
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
        return "default-src 'none'; script-src 'self'; form-action 'self' " . $origin . "; frame-ancestors 'none'";
    }

    private function policyOfTheAnswer(): string
    {
        $policy = $this->browser->getResponse()->headers->get('Content-Security-Policy');
        static::assertIsString($policy);

        return $policy;
    }
}
