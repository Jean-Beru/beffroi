<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Profiler;

use function array_keys;
use function array_map;
use Heidi\Bundle\Profiler\OpCollector;
use Heidi\Bundle\Profiler\OpProfile;
use Heidi\Bundle\Tests\Functional\Controller\BrowserTestCase;
use function implode;
use const PHP_URL_QUERY;
use function parse_str;
use function parse_url;
use function strlen;
use function substr;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Profiler\Profile;

/**
 * The panel of the provider (issue #152): what the collector of the bundle says of a request that
 * reached an endpoint, what it says of one that did not, and what it never says. The kernel behind the
 * browser is in debug, which is the one condition the panel is wired under.
 */
final class ProfilerPanelTest extends BrowserTestCase
{
    protected static function kernelOptions(): array
    {
        return [
            'debug' => true,
        ];
    }

    #[Test]
    public function theObservationsOfTheRequestAreGroupedUnderTheTabsTheyNamed(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        static::assertSame(['Request', 'Client', 'Interaction', 'Decision', 'Response', 'Provider'], array_keys($this->collector()->getTabs()));
    }

    /**
     * The endpoint is named by the route, which is where the planes of the provider are written down
     * (architecture §5.2), and the connection says what it brought.
     */
    #[Test]
    public function theEndpointSaysWhichRouteWasReachedAndWhatTheConnectionBrought(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        static::assertSame(
            [
                'route' => 'heidi_interaction_authorize',
                'method' => 'GET',
                'path' => '/authorize',
                'client certificate' => 'none',
                'DPoP proof' => 'none',
            ],
            $this->observation('Endpoint'),
        );
    }

    /**
     * OIDC Core §6.1: a request that came in the query came in the query, and the panel says so before
     * anything else, because from PAR and JAR on it is the one thing a browser stops showing.
     */
    #[Test]
    public function theAuthorizationRequestSaysHowItCameIn(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        static::assertSame('in the query of the browser', $this->observation('Authorization request')['how it came in']);
    }

    /**
     * Issue #98: what the panel says of a client is read off the client, the authentication method and
     * the two requirements included.
     */
    #[Test]
    public function theClientIsSaidAsItIsRegistered(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        $client = $this->observation('Client');
        static::assertSame('native-app', $client['client_id']);
        static::assertSame('none', $client['authentication method']);
        static::assertSame('required', $client['PKCE']);
        static::assertSame('not required', $client['pushed authorization request']);
    }

    /**
     * OIDC Core §3.1.2.1: the browser is sent to the login page, and the panel says why.
     */
    #[Test]
    public function theDecisionOfTheEndpointIsCollected(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        static::assertSame(
            [
                'outcome' => 'the user authenticates',
                'why' => 'no_session',
                'classes still short of' => 'none',
                'credentials that would reach one' => 'none',
            ],
            $this->observation('Decision'),
        );
    }

    /**
     * The toolbar of a host application carries an entry on the pages of the provider and on no other.
     */
    #[Test]
    public function aRequestThatReachedNoEndpointOfTheProviderIsNotCollected(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/host');

        // Then
        static::assertSame([], $this->observations());
    }

    /**
     * Decision 0006 and decision 0011: nothing a request carried that authenticates or names a person
     * is written down, whatever the panel shows beside it.
     */
    #[Test]
    public function nothingCollectedCarriesAValueThatAuthenticates(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'id_token_hint' => 'a.token.nobody-should-read',
        ]));

        // Then
        $collected = implode("\n", array_map(static fn (array $observation): string => implode("\n", $observation['entries']), $this->observations()));
        static::assertStringNotContainsString('nobody-should-read', $collected);
        static::assertStringNotContainsString(self::CODE_VERIFIER, $collected);
    }

    /**
     * The panel renders in the profiler of the application that installs the bundle, under its layout.
     */
    #[Test]
    public function thePanelRendersInTheProfiler(): void
    {
        // Given
        $this->browser->enableProfiler();
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $profile = $this->browser->getProfile();
        static::assertInstanceOf(Profile::class, $profile);

        // When
        $crawler = $this->browser->request('GET', '/_profiler/' . $profile->getToken(), [
            'panel' => OpCollector::NAME,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertStringContainsString('heidi_interaction_authorize', $crawler->filter('body')->text());
    }

    /**
     * The debug toolbar is rendered on its own, by a template of its own: a block of the panel that
     * needed anything of the panel's own context would fail there and nowhere else.
     */
    #[Test]
    public function theToolbarCarriesTheEntryOfTheProvider(): void
    {
        // Given
        $this->browser->enableProfiler();
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $profile = $this->browser->getProfile();
        static::assertInstanceOf(Profile::class, $profile);

        // When
        $crawler = $this->browser->request('GET', '/_wdt/' . $profile->getToken());

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertStringContainsString('Authorization request', $crawler->filter('body')->text());
    }

    /**
     * A kernel that is not in debug wires neither the panel nor anything that feeds it.
     */
    #[Test]
    public function nothingIsWiredWhenTheKernelIsNotInDebug(): void
    {
        // Given
        self::browser();

        // When
        $container = static::getContainer();

        // Then
        static::assertFalse($container->has(OpProfile::class));
    }

    /**
     * Issue #98 : ce que le fournisseur annonce est ce qui est branché. Le panneau lit le document de
     * découverte lui-même, donc il ne peut pas annoncer autre chose que l'endpoint de découverte.
     */
    #[Test]
    public function theProviderTabCarriesTheDiscoveryDocument(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        $served = $this->observation('What this provider serves');
        static::assertSame('https://op.test', $served['issuer']);
        static::assertSame(
            'authorization_code refresh_token client_credentials urn:ietf:params:oauth:grant-type:device_code',
            $served['grant_types_supported'],
        );
        static::assertSame('S256', $served['code_challenge_methods_supported']);
    }

    /**
     * Architecture §4.3 : une page du plan d'interaction ne porte que l'identifiant de l'interaction,
     * et tout ce que le client a demandé vit dans le dossier derrière lui.
     */
    #[Test]
    public function theInteractionOfAPageOfTheInteractionPlaneIsDetailed(): void
    {
        // Given
        $interaction = $this->beginAuthorization();
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $detailed = $this->observation('Interaction');
        static::assertSame($interaction, $detailed['interaction']);
        static::assertSame('waiting for the user to authenticate', $detailed['where it is']);
        static::assertSame('native-app', $detailed['client_id']);
        static::assertSame('openid profile', $detailed['scopes requested']);
        static::assertSame('S256', $detailed['PKCE']);
        static::assertSame('none yet', $detailed['session attached']);
    }

    /**
     * RFC 6749 §5.1 : ce que le point de jeton a répondu, membre par membre, sans aucune valeur de jeton.
     */
    #[Test]
    public function theAnswerOfTheTokenEndpointIsShownWithoutItsTokens(): void
    {
        // Given
        $code = $this->codeAllowedByAlice();
        $this->browser->enableProfiler();

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);

        // Then
        $body = $this->observation('Answer')['body'];
        static::assertStringContainsString('access_token=(present, withheld)', $body);
        static::assertStringContainsString('id_token=(present, withheld)', $body);
        static::assertStringContainsString('token_type="Bearer"', $body);
        static::assertStringContainsString('scope="openid profile"', $body);
    }

    /**
     * OIDC Core §2 : les claims que le client va lire, les claims de protocole en clair et ceux qui
     * portent l'utilisateur seulement nommés (décision 0011).
     */
    #[Test]
    public function theClaimsOfTheIdTokenAreShownAndThePersonalOnesOnlyNamed(): void
    {
        // Given
        $code = $this->codeAllowedByAlice();
        $this->browser->enableProfiler();

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);

        // Then
        $claims = $this->observation('ID token')['claims it carries'];
        static::assertStringContainsString('iss="https://op.test"', $claims);
        static::assertStringContainsString('aud="native-app"', $claims);
        static::assertStringContainsString('acr="1"', $claims);
        static::assertStringContainsString('amr=["pwd"]', $claims);
    }

    private function codeAllowedByAlice(): string
    {
        self::signingKey();
        $interaction = $this->beginAuthorization();
        $this->signIn(self::user('alice'));
        $consent = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($consent->selectButton('Allow')->form());
        $query = [];
        parse_str(self::string(parse_url(self::string($this->browser->getResponse()->headers->get('Location')), PHP_URL_QUERY)), $query);

        return self::string($query['code'] ?? null);
    }

    private function beginAuthorization(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $location = self::string($this->browser->getResponse()->headers->get('Location'));
        static::assertMatchesRegularExpression('#^/login\?interaction=#', $location);

        return substr($location, strlen('/login?interaction='));
    }

    /**
     * @return list<array{tab: string, heading: string, entries: array<string, string>}>
     */
    private function observations(): array
    {
        return $this->collector()->getObservations();
    }

    private function collector(): OpCollector
    {
        $profile = $this->browser->getProfile();
        static::assertInstanceOf(Profile::class, $profile, 'The request was served without a profile.');
        $collector = $profile->getCollector(OpCollector::NAME);
        static::assertInstanceOf(OpCollector::class, $collector);

        return $collector;
    }

    /**
     * @return array<string, string>
     */
    private function observation(string $heading): array
    {
        foreach ($this->observations() as $observation) {
            if ($observation['heading'] === $heading) {
                return $observation['entries'];
            }
        }
        static::fail('No observation is headed "' . $heading . '".');
    }
}
