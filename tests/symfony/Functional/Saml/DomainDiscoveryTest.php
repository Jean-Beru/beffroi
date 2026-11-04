<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use function preg_replace;
use function array_map;
use App\Http\InteractionPages;
use App\Tests\Symfony\Functional\Controller\PasskeyTestCase;
use Beffroi\Core\Domain\Credential\TotpCredential;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\TotpAlgorithmInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Closure;
use DateTimeImmutable;
use function intdiv;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-60 to S-63, Decision 0029
 */
final class DomainDiscoveryTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    private const string DEPLOYMENT_POLICY = "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'";

    protected static function kernelOptions(): array
    {
        return [
            'environment' => 'test_service_provider',
        ];
    }

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $dispatcher = $container->get('event_dispatcher');
            static::assertInstanceOf(EventDispatcherInterface::class, $dispatcher);
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
     * S-61
     */
    #[Test]
    public function theLoginPageAsksForTheAddressAlone(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $crawler = $this->loginPage($interaction);

        // Then
        static::assertSame(
            [1, 0, 0, 'username'],
            [
                $crawler->filter('form[data-step="address"] input[name="_address"]')->count(),
                $crawler->filter('input[name="_password"]')->count(),
                $crawler->filter('form[data-passkey]')->count(),
                $crawler->filter('input[name="_address"]')->attr('autocomplete'),
            ],
        );
    }

    /**
     * S-61
     */
    #[Test]
    public function anAddressOfAFederatedDomainIsSentToItsProviderWithoutAPasswordPrompt(): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $this->submitAddress($interaction, 'alice@example.org');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_SEE_OTHER, self::signOn($interaction)],
            [$response->getStatusCode(), self::locationOf($response)],
        );
    }

    /**
     * S-60, S-61
     */
    #[Test]
    #[DataProvider('provideSpellings')]
    public function theUnicodeAndUpperCaseFormsOfAFederatedDomainAreRoutedLikeItsALabel(string $address): void
    {
        // Given
        $interaction = $this->authorize();

        // When
        $this->submitAddress($interaction, $address);

        // Then
        static::assertSame(self::signOn($interaction), self::locationOf($this->browser->getResponse()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpellings(): iterable
    {
        yield 'its A-label' => ['alice@xn--bcher-kva.example'];
        yield 'a U-label' => ['alice@bücher.example'];
        yield 'a U-label in capitals' => ['alice@BÜCHER.EXAMPLE'];
        yield 'an A-label in capitals' => ['alice@XN--BCHER-KVA.example'];
        yield 'the other domain in capitals' => ['alice@EXAMPLE.Org'];
    }

    /**
     * S-62
     */
    #[Test]
    public function aLoginHintOfAFederatedDomainSkipsThePage(): void
    {
        // Given
        $interaction = $this->authorize([
            'login_hint' => 'alice@example.org',
        ]);

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, self::signOn($interaction)],
            [$response->getStatusCode(), self::locationOf($response)],
        );
    }

    /**
     * S-61
     */
    #[Test]
    #[DataProvider('provideOtherIdentifiers')]
    public function anotherDomainGetsTheUsualPage(string $identifier): void
    {
        // Given
        $interaction = $this->authorize();
        $this->submitAddress($interaction, $identifier);

        // When
        $crawler = $this->afterTheForm();

        // Then
        static::assertSame(
            [$identifier, 1],
            [$crawler->filter('input[name="_username"]')->attr('value'), $crawler->filter('input[name="_password"]')->count()],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherIdentifiers(): iterable
    {
        yield 'an address of another domain' => ['bob@umbrella.example'];
        yield 'an address of a subdomain of a federated domain' => ['bob@eu.example.org'];
        yield 'a username' => ['bob'];
    }

    /**
     * S-61
     */
    #[Test]
    #[DataProvider('provideAddresses')]
    public function anUnknownAddressAndAKnownOneGetTheSameAnswer(string $address): void
    {
        // Given
        $interaction = $this->authorize();
        $token = (string) $this->loginPage($interaction)->filter('form[data-step="address"] input[name="_token"]')->attr('value');
        $this->postAddress($interaction, $address, $token);
        $unknown = self::answer($this->browser->getResponse());
        self::personOf($address);

        // When
        $this->postAddress($interaction, $address, $token);

        // Then
        static::assertSame($unknown, self::answer($this->browser->getResponse()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAddresses(): iterable
    {
        yield 'of a federated domain' => ['carol@example.org'];
        yield 'of another domain' => ['carol@umbrella.example'];
    }

    /**
     * S-61
     */
    #[Test]
    #[DataProvider('provideHints')]
    public function theAddressPageIsTheSameWhetherTheHintNamesAPersonOrNot(string $hint): void
    {
        // Given
        $interaction = $this->authorize([
            'login_hint' => $hint,
        ]);
        $unknown = self::withoutTokens($this->loginPage($interaction)->html());
        self::user('carol@umbrella.example', $hint);

        // When
        $known = self::withoutTokens($this->loginPage($interaction)->html());

        // Then
        static::assertSame($unknown, $known);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHints(): iterable
    {
        yield 'a subject' => ['carol-subject'];
        yield 'an address of another domain' => ['carol@umbrella.example'];
    }

    /**
     * S-61, S-44
     */
    #[Test]
    public function anAddressWhoseDomainTheRuleRefusesComesBackToTheStep(): void
    {
        // Given
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'alice@example.org.');

        // When
        $crawler = $this->afterTheForm();

        // Then
        static::assertSame(
            ['address_unreadable', 1, 0],
            [
                $crawler->filter('p[data-error]')->attr('data-error'),
                $crawler->filter('form[data-step="address"]')->count(),
                $crawler->filter('input[name="_password"]')->count(),
            ],
        );
    }

    /**
     * S-61
     */
    #[Test]
    public function theUsualPageGoesBackToTheStepOfTheAddress(): void
    {
        // Given
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'bob@umbrella.example');
        $usual = $this->afterTheForm();

        // When
        $this->browser->submit($usual->selectButton('Use another address')->form());

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('form[data-step="address"]'));
    }

    /**
     * S-61, S-36, CSP Level 3 §6.3.2
     */
    #[Test]
    public function thePageOfTheAddressNamesTheSingleSignOnServiceOfTheProvider(): void
    {
        // Given
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->authorize();

        // When
        $this->loginPage($interaction);

        // Then
        static::assertSame(
            "default-src 'none'; script-src 'self'; img-src 'self'; form-action 'self' http://127.0.0.1 https://saml-idp.localhost; frame-ancestors 'none'",
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * S-63, Decision 0029
     */
    #[Test]
    public function aPasswordPresentedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        self::federated(self::userWithPassword('alice', self::PASSWORD));
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'alice');

        // When
        $this->submitLogin($interaction, 'alice', self::PASSWORD);

        // Then
        static::assertSame(
            [false, [AuthenticationFailureReason::FederatedDomain]],
            [$this->isBoundToASession(), self::failures()],
        );
    }

    /**
     * S-63, Decision 0029
     */
    #[Test]
    public function aPasskeyPresentedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $device = self::device();
        $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        self::federated($alice);
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'bob');
        self::forgetEvents();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        static::assertSame(
            [false, [AuthenticationFailureReason::FederatedDomain]],
            [$this->isBoundToASession(), self::failures()],
        );
    }

    /**
     * S-63, Decision 0029
     */
    #[Test]
    public function aCodePresentedForAPersonOfAFederatedDomainIsRefused(): void
    {
        // Given
        $secret = Totps::secret();
        $alice = $this->userWithTotp('alice', $secret);
        $interaction = $this->authorize();
        $this->submitAddress($interaction, 'alice');
        $this->submitLogin($interaction, 'alice', self::PASSWORD);
        self::federated($alice);

        // When
        $this->submitCode($interaction, $this->codeAt($secret, new DateTimeImmutable()));

        // Then
        static::assertSame(
            [false, [AuthenticationFailureReason::FederatedDomain]],
            [$this->isBoundToASession(), self::failures()],
        );
    }

    private static function withoutTokens(string $html): string
    {
        return (string) preg_replace('/name="(_token|_csrf_token)" value="[^"]*"/', 'name="$1"', $html);
    }

    /**
     * The sign-on of S-51 for that interaction, its reference set aside.
     */
    private static function signOn(string $interaction): string
    {
        return '/saml/sp/sign-on?interaction=' . $interaction . '&identity_provider=' . IdentityProviderDocuments::SIMPLESAMLPHP;
    }

    private function submitAddress(string $interaction, string $address): void
    {
        $form = $this->loginPage($interaction)->filter('form[data-step="address"]')->form();
        $form['_address'] = $address;
        $this->browser->submit($form);
    }

    private function postAddress(string $interaction, string $address, string $token): void
    {
        $this->browser->request('POST', '/login/address?interaction=' . $interaction, [
            '_token' => $token,
            '_address' => $address,
        ]);
    }

    private function submitLogin(string $interaction, string $username, string $password): void
    {
        $form = $this->loginPage($interaction)->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }

    private function submitCode(string $interaction, string $code): void
    {
        $crawler = $this->browser->request('GET', '/login/code', [
            'interaction' => $interaction,
        ]);
        $form = $crawler->selectButton('Continue')->form();
        $form['_code'] = $code;
        $this->browser->submit($form);
    }

    /**
     * @return array{int, string|null, string|false} status, location, body
     */
    private static function answer(Response $response): array
    {
        $content = $response->getContent();

        return [$response->getStatusCode(), self::locationOf($response), $content === false ? false : self::withoutReferences($content)];
    }

    /**
     * Sets aside the one-time reference of a sign-on (S-51).
     */
    private static function locationOf(Response $response): ?string
    {
        $location = $response->headers->get('Location');

        return $location === null ? null : self::withoutReferences($location);
    }

    /**
     * A reference is drawn again at each answer (S-51).
     */
    private static function withoutReferences(string $text): string
    {
        return (string) preg_replace('/&(amp;)?reference=[A-Za-z0-9_-]{43}/', '', $text);
    }

    private static function personOf(string $address): void
    {
        $person = self::user($address, $address . '-subject');
        $person->changeEmail(new EmailAddress($address), true, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($person);
    }

    private static function federated(User $user): void
    {
        $users = self::service('test.beffroi.users', UserRepositoryInterface::class);
        $person = $users->find($user->id) ?? static::fail('The person is gone.');
        $person->changeEmail(new EmailAddress($user->username . '@example.org'), true, self::now());
        $users->save($person);
    }

    /**
     * @return list<AuthenticationFailureReason> in the order they were announced
     */
    private static function failures(): array
    {
        return array_map(static fn (AuthenticationFailed $failed): AuthenticationFailureReason => $failed->reason, self::events(AuthenticationFailed::class));
    }

    private function userWithTotp(string $username, TotpSecret $secret): User
    {
        $user = self::userWithPassword($username, self::PASSWORD);
        $sealed = self::service('test.beffroi.secret_sealer', SecretSealerInterface::class)->seal(self::tenant(), $secret->bytes);
        $anHourAgo = new DateTimeImmutable('-1 hour');
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)
            ->save(new TotpCredential(
                Uuid::v7(),
                $user,
                $sealed,
                Totps::credential($user, new FakePasswordHasher())->backupCodes,
                intdiv($anHourAgo->getTimestamp(), TotpCredential::PERIOD),
                $anHourAgo,
            ));

        return $user;
    }

    private function codeAt(TotpSecret $secret, DateTimeImmutable $at): string
    {
        return self::service('test.beffroi.totp_algorithm', TotpAlgorithmInterface::class)
            ->codeAt($secret, intdiv($at->getTimestamp(), TotpCredential::PERIOD));
    }

    private static function accept(string $document): void
    {
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
                $document,
                null,
                self::currentSecond(),
            ));
    }
}
