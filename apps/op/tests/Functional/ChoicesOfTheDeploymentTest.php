<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use function json_decode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Issues #911 and #915: what a deployment of the image chooses, it names by environment, and the image is not
 * rebuilt for it, the roles of its tenant among them. A real environment variable wins over .env, as it does on a
 * deployment, so the variables are named before the kernel boots and given back after.
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
}
