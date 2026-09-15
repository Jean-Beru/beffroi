<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Command;

use function explode;
use Heidi\Bundle\Tests\Functional\Controller\BrowserTestCase;
use Heidi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Event\SigningKeyRotated;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Port\CredentialRepositoryInterface;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\SigningKeyProviderInterface;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use Heidi\Core\Port\UserRepositoryInterface;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_match;
use function sprintf;
use function str_repeat;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV4;

/**
 * Architecture §5.5: a fresh application is provisioned from the console only, the tenant first, then a
 * key and a user; nothing else writes before the first login.
 */
final class ProvisioningTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * The acceptance criterion of the commands, step 1: after a migration, the tenant of the
     * configuration becomes a row.
     */
    #[Test]
    public function theTenantOfTheConfigurationIsSynchronisedAsARow(): void
    {
        // Given
        self::dropTenant();

        // When
        $tester = self::console('heidi:tenant:synchronize');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('https://op.test', $tester->getDisplay());
        static::assertStringContainsString('The tenant "default" is synchronised', $tester->getDisplay());
    }

    /**
     * Step 4: the JWK Set publishes the key the console generated.
     */
    #[Test]
    public function theJwkSetPublishesTheKeyOfTheConsole(): void
    {
        // Given
        $kid = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        $jwks = self::json($this->browser->getResponse());
        static::assertIsArray($jwks['keys']);
        static::assertCount(1, $jwks['keys']);
        static::assertIsArray($jwks['keys'][0]);
        static::assertSame($kid, $jwks['keys'][0]['kid']);
        static::assertArrayNotHasKey('d', $jwks['keys'][0]);
    }

    /**
     * Step 3: the password typed twice on the terminal is never echoed.
     */
    #[Test]
    public function thePasswordTypedOnTheTerminalIsNeverEchoed(): void
    {
        // Given
        self::console('heidi:user:create', [
            'username' => 'alice',
        ]);

        // When
        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], [self::PASSWORD, self::PASSWORD]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringNotContainsString('correct horse', $tester->getDisplay());
    }

    /**
     * Step 5: the user signs in on the form with the password of the console.
     */
    #[Test]
    public function theUserOfTheConsoleSignsInOnTheForm(): void
    {
        // Given
        self::provisionAliceFromTheConsole();
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $form = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ])->selectButton('Sign in')
            ->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;

        // When
        $this->browser->submit($form);

        // Then
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        static::assertSame('/consent?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * Step 5: the flow of OIDC Core §3.1 runs on what the console wrote; the ID token is signed with the
     * key of the console and its "sub" is the subject the console printed.
     */
    #[Test]
    public function theIdTokenIsSignedWithTheKeyOfTheConsoleForTheSubjectItPrinted(): void
    {
        // Given
        ['kid' => $kid, 'subject' => $subject] = self::provisionAliceFromTheConsole();
        $code = $this->codeOfAliceSignedInOnTheForm();

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $idToken = explode('.', self::string(self::json($response)['id_token']));
        $header = json_decode(self::base64UrlDecode($idToken[0]), true, 4, JSON_THROW_ON_ERROR);
        static::assertIsArray($header);
        static::assertSame($kid, $header['kid']);
        $claims = json_decode(self::base64UrlDecode($idToken[1]), true, 4, JSON_THROW_ON_ERROR);
        static::assertIsArray($claims);
        static::assertSame($subject, $claims['sub']);
    }

    #[Test]
    public function theTenantIsSynchronisedOnceAndLeftAloneAfterwards(): void
    {
        // Given
        $tenant = self::tenant();

        // When
        $tester = self::console('heidi:tenant:synchronize');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame($tenant->id->toRfc4122(), self::displayed($tester, 'Identifier'));
        static::assertSame('op.test', self::displayed($tester, 'Name'));
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideCommandsThatNeedTheTenant')]
    public function nothingIsProvisionedBeforeTheTenantIs(string $name, array $input): void
    {
        // Given
        self::dropTenant();

        // When
        $tester = self::console($name, $input, [self::PASSWORD]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('has no row yet', $tester->getDisplay());
        static::assertStringContainsString('heidi:tenant:synchronize', $tester->getDisplay());
        static::assertSame(0, self::entityManager()->getConnection()->fetchOne('SELECT COUNT(*) FROM heidi_user'));
        static::assertDirectoryDoesNotExist(self::keyStorage());
    }

    /**
     * @return iterable<string, array{string, array<string, string|bool>}>
     */
    public static function provideCommandsThatNeedTheTenant(): iterable
    {
        yield 'heidi:keys:generate' => ['heidi:keys:generate', []];
        yield 'heidi:keys:list' => ['heidi:keys:list', []];
        yield 'heidi:user:create' => ['heidi:user:create', [
            'username' => 'alice',
        ]];
        yield 'heidi:user:set-password' => ['heidi:user:set-password', [
            'username' => 'alice',
            '--password-stdin' => true,
        ]];
    }

    /**
     * Architecture §3.3: a generated key is active and said so.
     */
    #[Test]
    public function aGeneratedKeyIsActive(): void
    {
        // When
        $tester = self::console('heidi:keys:generate');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $kid = self::displayed($tester, 'Key identifier');
        static::assertSame('RS256', self::displayed($tester, 'Algorithm'));
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringNotContainsString('is now retiring', $tester->getDisplay());
        $key = self::service('test.heidi.keys', SigningKeyRepositoryInterface::class)->find(self::tenant(), $kid) ?? static::fail('The key is not stored.');
        static::assertTrue($key->isActive());
        static::assertSame($kid, self::service('test.heidi.key_provider', SigningKeyProviderInterface::class)->activeKey(self::tenant(), SignatureAlgorithm::RS256)->key->kid);
    }

    /**
     * Architecture §3.3: the private key is sealed before it is written, never in clear.
     */
    #[Test]
    public function aGeneratedKeyIsSealedBeforeItIsWritten(): void
    {
        // When
        $kid = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');

        // Then
        static::assertStringNotContainsString('"d"', self::string(file_get_contents(self::keyStorage() . '/default/' . $kid . '.json')));
    }

    /**
     * Architecture §3.3: the rotation is announced, with the context of a process that is no request.
     */
    #[Test]
    public function aGeneratedKeyIsAnnounced(): void
    {
        // When
        $kid = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');

        // Then
        $events = self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events;
        static::assertCount(1, $events);
        static::assertInstanceOf(SigningKeyRotated::class, $events[0]);
        static::assertSame($kid, $events[0]->activated->kid);
        static::assertNull($events[0]->retiring);
        static::assertNull($events[0]->context->ipAddress);
        static::assertNull($events[0]->context->userAgent);
    }

    #[Test]
    public function theListSaysWhenThereIsNoPublishedKey(): void
    {
        // When
        $tester = self::console('heidi:keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('has no published key', $tester->getDisplay());
    }

    #[Test]
    public function generatingASecondKeyIsARotation(): void
    {
        // Given
        $first = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:generate');

        // Then
        $second = self::displayed($tester, 'Key identifier');
        static::assertNotSame($first, $second);
        static::assertStringContainsString(sprintf('The key "%s" was active and is now retiring', $first), self::flattened($tester));
        $keys = self::service('test.heidi.keys', SigningKeyRepositoryInterface::class);
        static::assertSame(KeyStatus::Retiring, $keys->find(self::tenant(), $first)?->status);
        static::assertSame(KeyStatus::Active, $keys->find(self::tenant(), $second)?->status);
    }

    #[Test]
    public function theListShowsThePublishedKeysWithTheirStatusAndDates(): void
    {
        // Given
        $first = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');
        $second = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');

        // When
        $tester = self::console('heidi:keys:list');

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertMatchesRegularExpression(sprintf('/^\s*%s\s+RS256\s+retiring\s+2026-\S+\s+2026-\S+\s*$/m', $first), $tester->getDisplay());
        static::assertMatchesRegularExpression(sprintf('/^\s*%s\s+RS256\s+active\s+2026-\S+\s*$/m', $second), $tester->getDisplay());
    }

    #[Test]
    public function aUserIsCreatedWithAGeneratedSubject(): void
    {
        // When
        $tester = self::console('heidi:user:create', [
            'username' => ' bob ',
            '--email' => 'bob@example.com',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('bob', self::displayed($tester, 'Username'));
        static::assertSame('bob@example.com (unverified)', self::displayed($tester, 'Email'));
        static::assertInstanceOf(UuidV4::class, Uuid::fromString(self::displayed($tester, 'Subject')));
        $user = self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'bob') ?? static::fail('The user is not stored.');
        static::assertFalse($user->emailVerified);
    }

    #[Test]
    public function aUserIsCreatedWithoutACredential(): void
    {
        // When
        self::console('heidi:user:create', [
            'username' => 'bob',
        ]);

        // Then
        $user = self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'bob') ?? static::fail('The user is not stored.');
        static::assertSame([], self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findByUser($user));
    }

    /**
     * Decision 0002: an imported identity keeps the subject its clients know.
     */
    #[Test]
    public function anImportedUserKeepsItsSubject(): void
    {
        // When
        $tester = self::console('heidi:user:create', [
            'username' => 'carol',
            '--subject' => 'carol-from-keycloak',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNotNull(self::service('test.heidi.users', UserRepositoryInterface::class)->findBySubject(self::tenant(), new Subject('carol-from-keycloak')));
    }

    #[Test]
    public function aUsernameIsNotTakenTwice(): void
    {
        // Given
        self::console('heidi:user:create', [
            'username' => 'carol',
        ]);

        // When
        $tester = self::console('heidi:user:create', [
            'username' => 'carol',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user named "carol" already exists', $tester->getDisplay());
    }

    #[Test]
    public function aSubjectIsNotTakenTwice(): void
    {
        // Given
        self::console('heidi:user:create', [
            'username' => 'carol',
            '--subject' => 'carol-from-keycloak',
        ]);

        // When
        $tester = self::console('heidi:user:create', [
            'username' => 'dave',
            '--subject' => 'carol-from-keycloak',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user with the subject "carol-from-keycloak" already exists', $tester->getDisplay());
        static::assertNull(self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'dave'));
    }

    /**
     * @param array<string, string|bool> $input
     */
    #[Test]
    #[DataProvider('provideInvalidUserOptions')]
    public function whatIsNotAnEmailOrASubjectIsRefusedBeforeAnythingIsWritten(array $input, string $message): void
    {
        // When
        $tester = self::console('heidi:user:create', [
            'username' => 'erin',
        ] + $input);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString($message, $tester->getDisplay());
        static::assertNull(self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'erin'));
    }

    /**
     * @return iterable<string, array{array<string, string|bool>, string}>
     */
    public static function provideInvalidUserOptions(): iterable
    {
        yield 'not an email address' => [[
            '--email' => 'not an address',
        ], 'is not a valid email address'];
        yield 'not a subject' => [[
            '--subject' => 'with a space',
        ], 'printable ASCII'];
    }

    /**
     * What a script does: the password on the standard input, its line ending dropped, nothing on the
     * command line.
     */
    #[Test]
    public function thePasswordIsReadFromTheStandardInputForScripts(): void
    {
        // Given
        $user = self::user('alice');

        // When
        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
            '--password-stdin' => true,
        ], [self::PASSWORD]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $credential = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user) ?? static::fail('No credential was created.');
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertTrue(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, self::PASSWORD));
        static::assertFalse(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, self::PASSWORD . "\n"));
    }

    #[Test]
    public function aSecondPasswordReplacesTheFirstOnTheSameCredential(): void
    {
        // Given
        $user = self::user('alice');
        self::console('heidi:user:set-password', [
            'username' => 'alice',
            '--password-stdin' => true,
        ], ['first password']);
        $first = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user)->id ?? static::fail('No credential was created.');
        self::reload();

        // When
        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], ['second password', 'second password']);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $credential = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user) ?? static::fail('The credential is gone.');
        static::assertTrue($first->equals($credential->id));
        static::assertTrue(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, 'second password'));
        static::assertFalse(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, 'first password'));
    }

    /**
     * @param array<string, string|bool> $input
     * @param list<string> $inputs
     */
    #[Test]
    #[DataProvider('providePasswordsRefused')]
    public function aPasswordThatIsNotConfirmedTooShortEmptyOrUnaskableIsRefused(array $input, array $inputs, bool $interactive, int $status, string $message): void
    {
        // Given
        $user = self::user('alice');

        // When
        $tester = self::console('heidi:user:set-password', $input, $inputs, $interactive);

        // Then
        static::assertSame($status, $tester->getStatusCode());
        static::assertStringContainsString($message, $tester->getDisplay());
        static::assertNull(self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user));
    }

    /**
     * @return iterable<string, array{array<string, string|bool>, list<string>, bool, int, string}>
     */
    public static function providePasswordsRefused(): iterable
    {
        $alice = [
            'username' => 'alice',
        ];
        $stdin = $alice + [
            '--password-stdin' => true,
        ];
        yield 'not confirmed' => [$alice, [self::PASSWORD, self::PASSWORD . 'r'], true, Command::INVALID, 'The two passwords differ.'];
        yield 'too short' => [$alice, ['short', 'short'], true, Command::INVALID, 'at least 8 characters'];
        yield 'empty on the terminal' => [$alice, ['', ''], true, Command::INVALID, 'The password is empty.'];
        yield 'empty on the standard input' => [$stdin, [''], true, Command::INVALID, 'The password is empty.'];
        yield 'too long' => [$stdin, [str_repeat('a', 4097)], true, Command::INVALID, 'at most 4096 bytes'];
        yield 'not askable' => [$alice, [], false, Command::INVALID, '--password-stdin'];
        yield 'unknown user' => [[
            'username' => 'nobody',
            '--password-stdin' => true,
        ], [self::PASSWORD], true, Command::FAILURE, 'There is no user named "nobody"'];
    }

    /**
     * Steps 1 to 3 of the acceptance criterion: the tenant, a key, alice with a password, from the console.
     *
     * @return array{kid: string, subject: string}
     */
    private static function provisionAliceFromTheConsole(): array
    {
        self::dropTenant();
        self::console('heidi:tenant:synchronize');
        $kid = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');
        $subject = self::displayed(self::console('heidi:user:create', [
            'username' => 'alice',
            '--email' => 'alice@example.com',
            '--email-verified' => true,
        ]), 'Subject');
        self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], [self::PASSWORD, self::PASSWORD]);

        return [
            'kid' => $kid,
            'subject' => $subject,
        ];
    }

    /**
     * The code the native client gets once alice signed in on the form and allowed.
     */
    private function codeOfAliceSignedInOnTheForm(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $form = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ])->selectButton('Sign in')
            ->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;
        $this->browser->submit($form);
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($crawler->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    /**
     * Runs a command of the bundle on the kernel of the test, what "bin/console" does; the inputs are the
     * lines of the terminal, or of the standard input.
     *
     * @param array<string, string|bool> $input
     * @param list<string> $inputs
     */
    private static function console(string $name, array $input = [], array $inputs = [], bool $interactive = true): CommandTester
    {
        $kernel = self::$kernel ?? static::fail('The kernel is not booted.');
        $application = new Application($kernel);
        $application->setAutoExit(false);
        $tester = new CommandTester($application->find($name));
        $tester->setInputs($inputs);
        $tester->execute($input, [
            'interactive' => $interactive,
        ]);
        self::reload();

        return $tester;
    }

    /**
     * The display as one line: what the console wrapped in a block is read as it was written.
     */
    private static function flattened(CommandTester $tester): string
    {
        return self::string(preg_replace('/\s*\n\s*!?\s*/', ' ', $tester->getDisplay(true)));
    }

    /**
     * The value of a line of a definition list, as the console printed it.
     */
    private static function displayed(CommandTester $tester, string $label): string
    {
        $display = $tester->getDisplay(true);
        static::assertSame(1, preg_match(sprintf('/^\s*%s\s+(\S.*?)\s*$/m', $label), $display, $matches), sprintf('"%s" is not displayed in: %s', $label, $display));

        return $matches[1];
    }

    /**
     * Before the first provisioning: the schema, and no tenant row.
     */
    private static function dropTenant(): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement('DELETE FROM heidi_tenant');
        self::reload();
    }

    private static function base64UrlDecode(string $value): string
    {
        return self::string(base64_decode(strtr($value, '-_', '+/'), true));
    }
}
