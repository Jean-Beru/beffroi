<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use DateTimeImmutable;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Core\Tests\Fixture\SoftwareAuthenticator;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * A browser with a software authenticator (architecture §7): the two ceremonies driven over HTTP the way
 * the script of the bundle drives them, the options fetched, the authenticator's answer posted as the form.
 * The origin of the authenticator is the issuer of the test kernel, whatever host the browser names.
 */
abstract class PasskeyTestCase extends BrowserTestCase
{
    protected const string ORIGIN = 'https://op.test';

    /**
     * A hardware key without a PIN, unless the test says otherwise.
     */
    protected static function device(bool $userVerified = false, bool $synced = false): SoftwareAuthenticator
    {
        return new SoftwareAuthenticator(self::ORIGIN, userVerified: $userVerified, backupEligible: $synced, backedUp: $synced);
    }

    /**
     * A passkey enrolled through the page of the account, from a session the browser holds; the browser
     * keeps that session.
     */
    protected function enrol(User $user, SoftwareAuthenticator $device, string $name = 'YubiKey 5', ?DateTimeImmutable $signedInAt = null): PasskeyCredential
    {
        $this->signIn($user, $signedInAt);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => $name,
            '_passkey' => $device->create($this->creationOptions()),
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));

        return self::passkeyOf($user, $device);
    }

    protected function passkeysPage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account/passkeys');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * The creation options the page fetches, as JSON.
     */
    protected function creationOptions(): string
    {
        $this->browser->request('POST', '/account/passkeys/options');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string($response->getContent());
    }

    /**
     * The request options the login page fetches, as JSON.
     */
    protected function requestOptions(string $interaction): string
    {
        $this->browser->request('POST', '/login/passkey/options?interaction=' . $interaction);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string($response->getContent());
    }

    /**
     * The passkey login as the login page does it: the options fetched, the assertion posted with the
     * token of the page.
     */
    protected function loginWithPasskey(string $interaction, SoftwareAuthenticator $device): void
    {
        $token = $this->loginPage($interaction)->filter('form[data-passkey="login"] input[name="_csrf_token"]')->attr('value');
        static::assertIsString($token);
        $this->postPasskeyLogin($interaction, $device->get($this->requestOptions($interaction)), $token);
    }

    protected function postPasskeyLogin(string $interaction, string $assertion, ?string $token): void
    {
        $this->browser->request('POST', '/login/passkey?interaction=' . $interaction, [
            '_csrf_token' => $token,
            '_passkey' => $assertion,
        ]);
    }

    /**
     * @param array<string, string|null> $parameters
     */
    protected function authorize(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters(parameters: $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));

        return self::redirectedInteraction($response);
    }

    protected function loginPage(string $interaction): Crawler
    {
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    /**
     * The browser forgets its cookies: what a sign-out leaves behind on the OP.
     */
    protected function forgetTheBrowser(): void
    {
        $this->browser->getCookieJar()->clear();
    }

    /**
     * The passkey of the device in the rows.
     */
    protected static function passkeyOf(User $user, SoftwareAuthenticator $device): PasskeyCredential
    {
        self::reload();

        return (
            self::service('test.heidi.credentials', CredentialRepositoryInterface::class)
                ->findByExternalId(self::tenant(), PasskeyCredential::class, $device->credentialId) ?? static::fail('The passkey is not in the rows.')
        );
    }

    /**
     * The session of the core the browser is bound to, read from the rows.
     */
    protected function boundSession(): AuthenticationSession
    {
        $id = $this->readHttpSession()->get(BrowserSession::AUTHENTICATION_SESSION_KEY);
        static::assertIsString($id, 'The browser is bound to no session.');
        self::reload();

        return (
            self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString($id)) ?? static::fail('The bound session is gone.')
        );
    }

    protected function isBoundToASession(): bool
    {
        return $this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY);
    }

    /**
     * The token the firewall stored in the HTTP session of the browser.
     */
    protected function securityToken(): TokenInterface
    {
        $serialized = $this->readHttpSession()->get('_security_heidi_interaction');
        static::assertIsString($serialized, 'The firewall stored no token.');
        $token = unserialize($serialized);
        static::assertInstanceOf(TokenInterface::class, $token);

        return $token;
    }

    /**
     * The active sessions of a user, from the rows.
     *
     * @return list<AuthenticationSession>
     */
    protected static function sessionsOf(string $username): array
    {
        self::reload();
        $user = self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), $username);
        if (! $user instanceof User) {
            return [];
        }

        return self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class)->findActiveByUser($user, new DateTimeImmutable());
    }

    /**
     * The events of a class that reached the event bus during the last request.
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    protected static function events(string $class): array
    {
        $events = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof $class) {
                $events[] = $event;
            }
        }

        return $events;
    }
}
