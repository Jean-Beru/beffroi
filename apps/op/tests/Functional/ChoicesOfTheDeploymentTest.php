<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use function array_key_last;
use function explode;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Response;
use function trim;

/**
 * Issues #911, #915 and #920: what a deployment of the image chooses, it names by environment, and the image is not
 * rebuilt for it, the roles of its tenant and the scopes of its APIs among them. A real environment variable wins over
 * .env, as it does on a deployment, so the variables are named before the kernel boots and given back after.
 */
final class ChoicesOfTheDeploymentTest extends BrowserTestCase
{
    private const array CHOICES = [
        'BEFFROI_REGISTRATION_MODE' => 'initial_access_token',
        'BEFFROI_TENANT_NAME' => 'Example Corporation',
        'BEFFROI_TENANT_LOGO_URI' => 'https://assets.example.com/mark.svg',
        'BEFFROI_TENANT_PRIMARY_COLOR' => '#0b5d1e',
        'BEFFROI_TENANT_PRIMARY_CONTENT_COLOR' => '#fafafa',
        'BEFFROI_TENANT_SELF_SERVED_CLAIMS' => '["nickname","locale"]',
        'BEFFROI_TENANT_SCOPES' => '["invoices.read","invoices.pay"]',
        'BEFFROI_SAML_IDENTITY_PROVIDER' => 'false',
        'BEFFROI_INTERACTION_LOGIN_HINT' => 'username',
    ];

    /**
     * @var array<string, array{mixed, mixed}>
     */
    private array $before = [];

    protected function setUp(): void
    {
        foreach (self::CHOICES as $name => $value) {
            $this->before[$name] = [$_SERVER[$name] ?? null, $_ENV[$name] ?? null];
            $_SERVER[$name] = $value;
            $_ENV[$name] = $value;
        }
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach ($this->before as $name => [$server, $environment]) {
            $_SERVER[$name] = $server;
            $_ENV[$name] = $environment;
        }
    }

    /**
     * RFC 7591, decision 0009: the mode a deployment names is the registration endpoint its tenant announces,
     * which is how a client reaches an image that declares none.
     */
    #[Test]
    public function theTenantAnnouncesTheRegistrationEndpointOfTheModeItNames(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $document = json_decode(self::string($this->browser->getResponse()->getContent()), true);
        static::assertIsArray($document);
        static::assertSame('https://op.test/register', $document['registration_endpoint'] ?? null);
    }

    /**
     * OIDC Discovery §3, issue beffroi-auth/beffroi#920: the scopes of the APIs a deployment names are scopes its
     * tenant hands out tokens for, announced after those of its claims, before any client registers them.
     */
    #[Test]
    public function theTenantAnnouncesTheScopesOfTheApisItNames(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $document = json_decode(self::string($this->browser->getResponse()->getContent()), true);
        static::assertIsArray($document);
        static::assertSame(
            ['openid', 'profile', 'email', 'address', 'phone', 'invoices.read', 'invoices.pay', 'offline_access'],
            $document['scopes_supported'] ?? null,
        );
    }

    /**
     * RFC 7591 §3.1, decision 0009, issue beffroi-auth/beffroi#920: a client that registers itself with an initial
     * access token of the console may register the scopes of the APIs the deployment names, which is how a relying
     * party of an image that declares no client is given them.
     */
    #[Test]
    public function aClientThatRegistersItselfMayRegisterTheScopesOfTheApisItNames(): void
    {
        // Given
        $token = $this->initialAccessToken();

        // When
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
            ],
            content: json_encode([
                'client_name' => 'A relying party of the deployment',
                'redirect_uris' => ['https://rp.example.com/callback'],
                'token_endpoint_auth_method' => 'client_secret_basic',
                'grant_types' => ['authorization_code', 'refresh_token'],
                'scope' => 'openid profile email offline_access invoices.read invoices.pay',
            ], JSON_THROW_ON_ERROR),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));
    }

    #[Test]
    public function aPageShowsTheMarkItNamesUnderTheNameItNames(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $logo = $this->accountHome()->filter('img[data-tenant="logo"]');

        // Then
        static::assertSame('https://assets.example.com/mark.svg', $logo->attr('src'));
        static::assertSame('Example Corporation', $logo->attr('alt'));
    }

    /**
     * Decision 0030, issue beffroi-auth/beffroi#452: a list of the configuration is a JSON document of the
     * environment, here the claims a person may change of themselves.
     */
    #[Test]
    public function aPersonChangesOfThemselvesTheClaimsItOpens(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $page = $this->page('/account/profile');

        // Then
        static::assertSame(['nickname', 'locale'], $page->filter('form[data-editable]')->extract(['data-editable']));
    }

    #[Test]
    public function aPageIsDrawnInTheColoursItNames(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $style = $this->accountHome()->filter('head style')->text();

        // Then
        static::assertStringContainsString('--color-primary: #0b5d1e; --color-primary-content: #fafafa;', $style);
    }

    /**
     * Decision 0030, issue beffroi-auth/beffroi#915: a role of the tenant is a variable too, here the SAML identity
     * provider the image is until its deployment turns it off, which leaves the tenant no SAML key to draw, its service
     * provider being off as in every image.
     */
    #[Test]
    public function aDeploymentThatTurnsItsSamlRolesOffDrawsNoSamlKey(): void
    {
        // Given
        $application = new Application(self::$kernel ?? static::fail('The kernel is not booted.'));
        $application->setAutoExit(false);
        $keys = new CommandTester($application->find('beffroi:keys:generate'));

        // When
        $keys->execute([
            '--algorithm' => 'SAML-SIGNING',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $keys->getStatusCode());
    }

    /**
     * OIDC Core §3.1.2.1, issue beffroi-auth/beffroi#915: the "login_hint" of a request names the user the way the
     * deployment says, here the name the user signs in with, which the login page offers.
     */
    #[Test]
    public function theLoginPageOffersTheUserTheHintNamesTheWayTheDeploymentReadsIt(): void
    {
        // Given
        self::user();
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'consent-app',
            'redirect_uri' => 'https://consent.test/callback',
            'response_type' => 'code',
            'scope' => 'openid profile',
            'state' => 'state-of-the-client',
            'nonce' => 'nonce-of-the-client',
            'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S256',
            'login_hint' => 'alice',
        ]);

        // When
        $page = $this->browser->followRedirect();

        // Then
        static::assertSame('alice', $page->filter('input#username')->attr('value'));
    }

    /**
     * An initial access token of the tenant (RFC 7591 §1.2), issued by the console as a deployment issues one: the
     * command prints the value once, on the last line it writes.
     */
    private function initialAccessToken(): string
    {
        $application = new Application(self::$kernel ?? static::fail('The kernel is not booted.'));
        $application->setAutoExit(false);
        $issue = new CommandTester($application->find('beffroi:client:token:issue'));
        $issue->execute([
            'name' => 'The team that integrates',
        ]);
        $issue->assertCommandIsSuccessful();
        $lines = explode("\n", trim($issue->getDisplay()));

        return trim($lines[array_key_last($lines)]);
    }
}
