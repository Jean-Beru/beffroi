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
    /**
     * The acceptance criterion of the commands: after a migration, five console calls give an OP a client
     * can sign in on, and the flow of OIDC Core §3.1 runs on what they wrote.
     */
    #[Test]
    public function aFreshApplicationIsProvisionedFromTheConsoleAndServesTheCodeFlow(): void
    {
        self::dropTenant();

        // 1. the tenant of the configuration, as a row
        $tester = self::console('heidi:tenant:synchronize');
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('https://op.test', $tester->getDisplay());
        static::assertStringContainsString('The tenant "default" is synchronised', $tester->getDisplay());

        // 2. a key, sealed and active
        $tester = self::console('heidi:keys:generate');
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $kid = self::displayed($tester, 'Key identifier');

        // 3. a user, with a password typed twice on the terminal
        $tester = self::console('heidi:user:create', [
            'username' => 'alice',
            '--email' => 'alice@example.com',
            '--email-verified' => true,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $subject = self::displayed($tester, 'Subject');
        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], ['correct horse battery staple', 'correct horse battery staple']);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringNotContainsString('correct horse', $tester->getDisplay(), 'The password is never echoed.');

        // 4. the discovery document and the JWK Set publish what the console wrote
        $this->browser->request('GET', '/jwks');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        $jwks = self::json($this->browser->getResponse());
        static::assertIsArray($jwks['keys']);
        static::assertCount(1, $jwks['keys']);
        static::assertIsArray($jwks['keys'][0]);
        static::assertSame($kid, $jwks['keys'][0]['kid']);
        static::assertArrayNotHasKey('d', $jwks['keys'][0]);

        // 5. the user signs in on the form with the password of the console, and the flow goes through
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $form = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ])->selectButton('Sign in')
            ->form();
        $form['_username'] = 'alice';
        $form['_password'] = 'correct horse battery staple';
        $this->browser->submit($form);
        static::assertSame('/login?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        static::assertSame('/consent?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($crawler->selectButton('Allow')->form());
        $code = self::redirectedQuery($this->browser->getResponse())['code'];

        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $tokens = self::json($response);
        $header = json_decode(self::base64UrlDecode(explode('.', self::string($tokens['id_token']))[0]), true, 4, JSON_THROW_ON_ERROR);
        static::assertIsArray($header);
        static::assertSame($kid, $header['kid'], 'The ID token is signed with the key of the console.');
        $claims = json_decode(self::base64UrlDecode(explode('.', self::string($tokens['id_token']))[1]), true, 4, JSON_THROW_ON_ERROR);
        static::assertIsArray($claims);
        static::assertSame($subject, $claims['sub'], 'The "sub" is the subject the console printed.');
    }

    #[Test]
    public function theTenantIsSynchronisedOnceAndLeftAloneAfterwards(): void
    {
        $tenant = self::tenant();
        $tester = self::console('heidi:tenant:synchronize');

        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame($tenant->id->toRfc4122(), self::displayed($tester, 'Identifier'));
        static::assertSame('op.test', self::displayed($tester, 'Name'));
    }

    #[Test]
    public function nothingIsProvisionedBeforeTheTenantIs(): void
    {
        self::dropTenant();

        foreach ([
            ['heidi:keys:generate', []],
            ['heidi:keys:list', []],
            ['heidi:user:create', [
                'username' => 'alice',
            ]],
            ['heidi:user:set-password', [
                'username' => 'alice',
                '--password-stdin' => true,
            ]],
        ] as [$name, $input]) {
            $tester = self::console($name, $input, ['correct horse battery staple']);
            static::assertSame(Command::FAILURE, $tester->getStatusCode(), $name);
            static::assertStringContainsString('has no row yet', $tester->getDisplay(), $name);
            static::assertStringContainsString('heidi:tenant:synchronize', $tester->getDisplay(), $name);
        }
        static::assertSame(0, self::entityManager()->getConnection()->fetchOne('SELECT COUNT(*) FROM heidi_user'));
        static::assertDirectoryDoesNotExist(self::keyStorage());
    }

    /**
     * Architecture §3.3: the private key is sealed before it is written, the public one is published, the
     * rotation is announced.
     */
    #[Test]
    public function aGeneratedKeyIsSealedActiveAndAnnounced(): void
    {
        $tester = self::console('heidi:keys:generate');

        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $kid = self::displayed($tester, 'Key identifier');
        static::assertSame('RS256', self::displayed($tester, 'Algorithm'));
        static::assertSame('active', self::displayed($tester, 'Status'));
        static::assertStringNotContainsString('is now retiring', $tester->getDisplay());
        $key = self::service('test.heidi.keys', SigningKeyRepositoryInterface::class)->find(self::tenant(), $kid) ?? static::fail('The key is not stored.');
        static::assertTrue($key->isActive());
        static::assertStringNotContainsString('"d"', self::string(file_get_contents(self::keyStorage() . '/default/' . $kid . '.json')), 'The private member is sealed, never written in clear.');
        static::assertSame($kid, self::service('test.heidi.key_provider', SigningKeyProviderInterface::class)->activeKey(self::tenant(), SignatureAlgorithm::RS256)->key->kid);
        $events = self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events;
        static::assertCount(1, $events);
        static::assertInstanceOf(SigningKeyRotated::class, $events[0]);
        static::assertSame($kid, $events[0]->activated->kid);
        static::assertNull($events[0]->retiring);
        static::assertNull($events[0]->context->ipAddress);
        static::assertNull($events[0]->context->userAgent);
    }

    #[Test]
    public function generatingASecondKeyIsARotationAndTheListShowsBoth(): void
    {
        $tester = self::console('heidi:keys:list');
        static::assertSame(Command::SUCCESS, $tester->getStatusCode());
        static::assertStringContainsString('has no published key', $tester->getDisplay());

        $first = self::displayed(self::console('heidi:keys:generate'), 'Key identifier');
        $tester = self::console('heidi:keys:generate');
        $second = self::displayed($tester, 'Key identifier');
        static::assertNotSame($first, $second);
        static::assertStringContainsString(sprintf('The key "%s" was active and is now retiring', $first), self::flattened($tester));

        $keys = self::service('test.heidi.keys', SigningKeyRepositoryInterface::class);
        static::assertSame(KeyStatus::Retiring, $keys->find(self::tenant(), $first)?->status);
        static::assertSame(KeyStatus::Active, $keys->find(self::tenant(), $second)?->status);

        $tester = self::console('heidi:keys:list');
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertMatchesRegularExpression(sprintf('/^\s*%s\s+RS256\s+retiring\s+2026-\S+\s+2026-\S+\s*$/m', $first), $tester->getDisplay());
        static::assertMatchesRegularExpression(sprintf('/^\s*%s\s+RS256\s+active\s+2026-\S+\s*$/m', $second), $tester->getDisplay());
    }

    #[Test]
    public function aUserIsCreatedWithoutACredentialAndWithAGeneratedSubject(): void
    {
        $tester = self::console('heidi:user:create', [
            'username' => ' bob ',
            '--email' => 'bob@example.com',
        ]);

        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame('bob', self::displayed($tester, 'Username'));
        static::assertSame('bob@example.com (unverified)', self::displayed($tester, 'Email'));
        static::assertInstanceOf(UuidV4::class, Uuid::fromString(self::displayed($tester, 'Subject')));
        $user = self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'bob') ?? static::fail('The user is not stored.');
        static::assertFalse($user->emailVerified);
        static::assertSame([], self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findByUser($user));
    }

    /**
     * Decision 0002: an imported identity keeps the subject its clients know.
     */
    #[Test]
    public function anImportedUserKeepsItsSubjectAndNeitherIsTakenTwice(): void
    {
        $tester = self::console('heidi:user:create', [
            'username' => 'carol',
            '--subject' => 'carol-from-keycloak',
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNotNull(self::service('test.heidi.users', UserRepositoryInterface::class)->findBySubject(self::tenant(), new Subject('carol-from-keycloak')));

        $tester = self::console('heidi:user:create', [
            'username' => 'carol',
        ]);
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user named "carol" already exists', $tester->getDisplay());

        $tester = self::console('heidi:user:create', [
            'username' => 'dave',
            '--subject' => 'carol-from-keycloak',
        ]);
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('A user with the subject "carol-from-keycloak" already exists', $tester->getDisplay());
        static::assertNull(self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'dave'));
    }

    #[Test]
    public function whatIsNotAnEmailOrASubjectIsRefusedBeforeAnythingIsWritten(): void
    {
        $tester = self::console('heidi:user:create', [
            'username' => 'erin',
            '--email' => 'not an address',
        ]);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('is not a valid email address', $tester->getDisplay());

        $tester = self::console('heidi:user:create', [
            'username' => 'erin',
            '--subject' => 'with a space',
        ]);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('printable ASCII', $tester->getDisplay());

        static::assertNull(self::service('test.heidi.users', UserRepositoryInterface::class)->findByUsername(self::tenant(), 'erin'));
    }

    /**
     * What a script does: the password on the standard input, its line ending dropped, nothing on the
     * command line.
     */
    #[Test]
    public function thePasswordIsReadFromTheStandardInputForScripts(): void
    {
        $user = self::user('alice');
        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
            '--password-stdin' => true,
        ], ['correct horse battery staple']);

        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $credential = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user) ?? static::fail('No credential was created.');
        static::assertSame(PasswordAlgorithm::Argon2id, $credential->hash->algorithm);
        static::assertTrue(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, 'correct horse battery staple'));
        static::assertFalse(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, "correct horse battery staple\n"));
    }

    #[Test]
    public function aSecondPasswordReplacesTheFirstOnTheSameCredential(): void
    {
        $user = self::user('alice');
        self::console('heidi:user:set-password', [
            'username' => 'alice',
            '--password-stdin' => true,
        ], ['first password']);
        $first = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user)->id ?? static::fail('No credential was created.');
        self::reload();

        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], ['second password', 'second password']);

        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        $credential = self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user) ?? static::fail('The credential is gone.');
        static::assertTrue($first->equals($credential->id));
        static::assertTrue(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, 'second password'));
        static::assertFalse(self::service('test.heidi.password_hasher', PasswordHasherInterface::class)->verify($credential->hash, 'first password'));
    }

    #[Test]
    public function aPasswordThatIsNotConfirmedTooShortEmptyOrUnaskableIsRefused(): void
    {
        $user = self::user('alice');

        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], ['correct horse battery staple', 'correct horse battery stapler']);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('The two passwords differ.', $tester->getDisplay());

        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], ['short', 'short']);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('at least 8 characters', $tester->getDisplay());

        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], ['', '']);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('The password is empty.', $tester->getDisplay());

        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
            '--password-stdin' => true,
        ], ['']);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('The password is empty.', $tester->getDisplay());

        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
            '--password-stdin' => true,
        ], [str_repeat('a', 4097)]);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('at most 4096 bytes', $tester->getDisplay());

        $tester = self::console('heidi:user:set-password', [
            'username' => 'alice',
        ], [], interactive: false);
        static::assertSame(Command::INVALID, $tester->getStatusCode());
        static::assertStringContainsString('--password-stdin', $tester->getDisplay());

        $tester = self::console('heidi:user:set-password', [
            'username' => 'nobody',
            '--password-stdin' => true,
        ], ['correct horse battery staple']);
        static::assertSame(Command::FAILURE, $tester->getStatusCode());
        static::assertStringContainsString('There is no user named "nobody"', $tester->getDisplay());

        static::assertNull(self::service('test.heidi.credentials', CredentialRepositoryInterface::class)->findPasswordCredential($user));
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
