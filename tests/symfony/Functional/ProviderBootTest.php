<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional;

use DateTimeImmutable;
use App\Messenger\EventBusDispatcher;
use App\Security\CorePasswordHasher;
use App\Security\SecurityUser;
use App\Tenant\TenantFactory;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Discovery\JwksHandler;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;

/**
 * The kernel boots with the full configuration of tests/symfony/config/config_test.yml, and what the
 * provider wires today answers: the tenant, the clients, the hasher, the keys sealed by the configured
 * KMS and stored as files, the event dispatcher on the event bus.
 */
final class ProviderBootTest extends DatabaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        new Filesystem()->remove(self::keyStorage());
    }

    protected function tearDown(): void
    {
        // Before the parent, which shuts the kernel down: keyStorage() asks the container where it
        // writes, and a container that is down would be booted again just to answer.
        new Filesystem()->remove(self::keyStorage());
        parent::tearDown();
    }

    /**
     * Architecture §5.1: the tenant is the configuration; its identifier is derived from its slug.
     */
    #[Test]
    public function theTenantComesFromTheConfiguration(): void
    {
        // When
        $tenant = self::tenant();

        // Then
        static::assertSame('https://op.test', (string) $tenant->issuer);
        static::assertSame('default', $tenant->slug);
        static::assertSame('op.test', $tenant->name);
        static::assertTrue($tenant->id->equals(TenantFactory::identifier('default')));
    }

    /**
     * Architecture §5.1: clients declared in the configuration.
     */
    #[Test]
    public function aConfidentialClientComesFromTheConfiguration(): void
    {
        // Given
        $clients = self::service('test.beffroi.clients', ClientRepositoryInterface::class);

        // When
        $demo = $clients->findByClientId(self::tenant(), 'oidc-demo') ?? static::fail('The oidc-demo client is configured.');

        // Then
        static::assertSame('Demo application', $demo->registration->presentation->name);
        static::assertSame('client_secret_basic', $demo->registration->authenticationMethod->name());
        static::assertFalse($demo->registration->requiresConsent);
        static::assertTrue($demo->registration->requiresPkce);
    }

    /**
     * Decision 0008: the PKCE exception is declared per client.
     */
    #[Test]
    public function aClientWithoutThePkceRequirementComesFromTheConfiguration(): void
    {
        // Given
        $clients = self::service('test.beffroi.clients', ClientRepositoryInterface::class);

        // When
        $legacy = $clients->findByClientId(self::tenant(), 'legacy-app') ?? static::fail('The legacy-app client is configured.');

        // Then
        static::assertFalse($legacy->registration->requiresPkce);
        static::assertSame('client_secret_post', $legacy->registration->authenticationMethod->name());
    }

    /**
     * Architecture §5.1: the secret is hashed by the hasher of the core when the client is loaded.
     */
    #[Test]
    public function theSecretOfAConfiguredClientIsHashedByTheHasherOfTheCore(): void
    {
        // Given
        $clients = self::service('test.beffroi.clients', ClientRepositoryInterface::class);
        $hasher = self::service('test.beffroi.password_hasher', PasswordHasherInterface::class);

        // When
        $demo = $clients->findByClientId(self::tenant(), 'oidc-demo') ?? static::fail('The oidc-demo client is configured.');

        // Then
        static::assertInstanceOf(HashedClientSecret::class, $demo->secret);
        static::assertSame(Argon2id::NAME, $demo->secret->hash->algorithm->name());
        static::assertTrue($hasher->verify($demo->secret->hash, 'demo-secret-of-at-least-32-characters-long'));
    }

    #[Test]
    public function aPublicClientComesFromTheConfiguration(): void
    {
        // Given
        $clients = self::service('test.beffroi.clients', ClientRepositoryInterface::class);

        // When
        $native = $clients->findByClientId(self::tenant(), 'native-app') ?? static::fail('The native-app client is configured.');

        // Then
        static::assertSame('native-app', $native->registration->presentation->name);
        static::assertSame('none', $native->registration->authenticationMethod->name());
        static::assertTrue($native->registration->requiresConsent);
    }

    #[Test]
    public function anUnknownClientIsNotFound(): void
    {
        // Given
        $clients = self::service('test.beffroi.clients', ClientRepositoryInterface::class);

        // When / Then
        static::assertNull($clients->findByClientId(self::tenant(), 'unknown'));
    }

    #[Test]
    public function theClientAuthenticatorIsWired(): void
    {
        // When / Then
        static::assertInstanceOf(ClientAuthenticator::class, self::getContainer()->get('test.beffroi.client_authenticator'));
    }

    /**
     * Architecture §5.4: the security component hashes the passwords of the users of the provider with the
     * hasher of the core, mapped by the provider and not by the application.
     */
    #[Test]
    public function theSecurityComponentHashesTheUsersOfTheProviderWithTheHasherOfTheCore(): void
    {
        // Given
        $factory = self::service('test.beffroi.password_hasher_factory', PasswordHasherFactoryInterface::class);

        // When
        $hasher = $factory->getPasswordHasher(SecurityUser::class);

        // Then
        static::assertInstanceOf(CorePasswordHasher::class, $hasher);
    }

    /**
     * Architecture §5.4: what the security component hashes, the core verifies, and the other way round.
     */
    #[Test]
    public function aHashOfTheSecurityComponentIsAHashOfTheCore(): void
    {
        // Given
        $hasher = self::service('test.beffroi.password_hasher_factory', PasswordHasherFactoryInterface::class)->getPasswordHasher(SecurityUser::class);
        $core = self::service('test.beffroi.password_hasher', PasswordHasherInterface::class);

        // When
        $encoded = $hasher->hash('correct horse battery staple');

        // Then
        $hash = self::service('test.beffroi.core_password_hasher', CorePasswordHasher::class)->decode($encoded) ?? static::fail('The hash is one of the core.');
        static::assertSame(Argon2id::NAME, $hash->algorithm->name());
        static::assertTrue($core->verify($hash, 'correct horse battery staple'));
        static::assertTrue($hasher->verify($encoded, 'correct horse battery staple'));
    }

    #[Test]
    public function aTenantWithoutKeysPublishesNothing(): void
    {
        // Given
        $jwks = self::service('test.beffroi.jwks', JwksHandler::class);

        // When
        $response = $jwks->handle(self::tenant());

        // Then
        static::assertSame([], $response->keys->keys);
    }

    /**
     * Architecture §3.3 and §5.1: a key generated by the take-over is sealed by the KMS of the configuration
     * and stored under "keys.storage".
     */
    #[Test]
    public function aRotatedKeyIsSealedAndStored(): void
    {
        // Given
        $takeOver = self::service('test.beffroi.key_take_over', KeyTakeOver::class);

        // When
        $key = $takeOver->rotate(self::tenant(), Algorithms::rs256(), new RequestContext(new DateTimeImmutable(), '127.0.0.1', 'phpunit'));

        // Then
        static::assertFileExists(self::keyStorage() . '/default/' . $key->kid . '.json');
    }

    /**
     * Architecture §4.8: a rotated key is published by the JWK Set handler on the next read, public
     * members only.
     */
    #[Test]
    public function aRotatedKeyIsPublishedOnTheNextRead(): void
    {
        // Given
        $tenant = self::tenant();
        $key = self::service('test.beffroi.key_take_over', KeyTakeOver::class)
            ->rotate($tenant, Algorithms::rs256(), new RequestContext(new DateTimeImmutable(), '127.0.0.1', 'phpunit'));

        // When
        $published = json_decode(self::service('test.beffroi.jwks', JwksHandler::class)->handle($tenant)->toJson(), true, 8, JSON_THROW_ON_ERROR);

        // Then
        static::assertIsArray($published);
        static::assertIsArray($published['keys']);
        static::assertCount(1, $published['keys']);
        static::assertIsArray($published['keys'][0]);
        static::assertSame($key->kid, $published['keys'][0]['kid']);
        static::assertArrayNotHasKey('d', $published['keys'][0]);
    }

    /**
     * Architecture §5.6: the dispatcher of the core is the one that replays on the event bus.
     */
    #[Test]
    public function theEventDispatcherOfTheCoreIsTheEventBusOne(): void
    {
        // When / Then
        static::assertInstanceOf(EventBusDispatcher::class, self::getContainer()->get('test.beffroi.event_bus_dispatcher'));
    }

    /**
     * Architecture §5.6: the core and the module announce in PSR-14, the provider replays on the event bus,
     * where the handlers of the application receive them; the dispatcher of the kernel hears nothing.
     */
    #[Test]
    public function theEventsOfTheCoreAndOfTheModuleGoToTheEventBus(): void
    {
        // Given
        $authenticator = self::service('test.beffroi.client_authenticator', ClientAuthenticator::class);
        $recorder = self::service(RecordingEventHandler::class, RecordingEventHandler::class);

        // When
        try {
            $authenticator->authenticate(
                self::tenant(),
                'https://op.test/token',
                null,
                [
                    'client_id' => 'oidc-demo',
                    'client_secret' => 'wrong-secret-of-at-least-32-characters-long',
                ],
                new RequestContext(new DateTimeImmutable(), '127.0.0.1', 'phpunit'),
            );
            static::fail('A wrong secret is refused.');
        } catch (InvalidClientException) {
        }

        // Then
        static::assertCount(1, $recorder->events);
        static::assertInstanceOf(ClientAuthenticationFailed::class, $recorder->events[0]);
        static::assertSame('oidc-demo', $recorder->events[0]->clientId);
    }

    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }
}
