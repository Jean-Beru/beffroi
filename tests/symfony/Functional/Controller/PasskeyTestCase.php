<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use DateTimeImmutable;
use App\Http\BrowserSession;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Architecture §7
 */
abstract class PasskeyTestCase extends BrowserTestCase
{
    protected const string ORIGIN = 'https://op.test';

    protected static function device(bool $userVerified = false, bool $synced = false): SoftwareAuthenticator
    {
        return new SoftwareAuthenticator(self::ORIGIN, userVerified: $userVerified, backupEligible: $synced, backedUp: $synced);
    }

    protected function enrol(User $user, SoftwareAuthenticator $device, string $name = 'YubiKey 5', ?DateTimeImmutable $signedInAt = null): PasskeyCredential
    {
        $playedAt = self::currentSecond();
        if ($signedInAt !== null) {
            self::mockTime($signedInAt);
        }
        $this->signIn($user, $signedInAt);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => $name,
            '_passkey' => $device->create($this->creationOptions()),
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
        if ($signedInAt !== null) {
            self::mockTime($playedAt);
        }

        return self::passkeyOf($user, $device);
    }

    protected function passkeysPage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account/passkeys');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    protected function creationOptions(): string
    {
        $this->browser->request('POST', '/account/passkeys/options');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string($response->getContent());
    }

    protected function requestOptions(string $interaction): string
    {
        $this->browser->request('POST', '/login/passkey/options?interaction=' . $interaction);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string($response->getContent());
    }

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

    protected function forgetTheBrowser(): void
    {
        $this->browser->getCookieJar()->clear();
    }

    protected static function passkeyOf(User $user, SoftwareAuthenticator $device): PasskeyCredential
    {
        self::reload();

        return (
            self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
                ->findByExternalId(self::tenant(), PasskeyCredential::class, $device->credentialId) ?? static::fail('The passkey is not in the rows.')
        );
    }

    protected function boundSession(): AuthenticationSession
    {
        $id = $this->readHttpSession()->get(BrowserSession::AUTHENTICATION_SESSION_KEY);
        static::assertIsString($id, 'The browser is bound to no session.');
        self::reload();

        return (
            self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString($id)) ?? static::fail('The bound session is gone.')
        );
    }

    protected function isBoundToASession(): bool
    {
        return $this->readHttpSession()->has(BrowserSession::AUTHENTICATION_SESSION_KEY);
    }

    protected function securityToken(): TokenInterface
    {
        $serialized = $this->readHttpSession()->get('_security_beffroi_interaction');
        static::assertIsString($serialized, 'The firewall stored no token.');
        $token = unserialize($serialized);
        static::assertInstanceOf(TokenInterface::class, $token);

        return $token;
    }

    /**
     * @return list<AuthenticationSession>
     */
    protected static function sessionsOf(string $username): array
    {
        self::reload();
        $user = self::service('test.beffroi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), $username);
        if (! $user instanceof User) {
            return [];
        }

        return self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->findActiveByUser($user, new DateTimeImmutable());
    }
}
