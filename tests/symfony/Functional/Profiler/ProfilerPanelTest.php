<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Profiler;

use function array_keys;
use function array_map;
use function base64_encode;
use App\Profiler\OpCollector;
use App\Profiler\OpProfile;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use function implode;
use const PHP_URL_QUERY;
use function parse_str;
use function parse_url;
use function strlen;
use function substr;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Profiler\Profile;

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
     * Architecture §5.2
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
                'route' => 'beffroi_interaction_authorize',
                'method' => 'GET',
                'path' => '/authorize',
                'client certificate' => 'none',
                'DPoP proof' => 'none',
            ],
            $this->observation('Endpoint'),
        );
    }

    /**
     * OIDC Core §6.1
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
     * OIDC Core §3.1.2.1
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
     * OIDC Core §3.1.2.4, §5.5
     */
    #[Test]
    public function theDecisionToAskForAConsentSaysTheClaimsAskedForByName(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'scope' => 'openid',
            'claims' => '{"userinfo": {"email": null}}',
        ]));

        // Then
        static::assertSame(
            [
                'outcome' => 'the user is asked to consent',
                'why' => 'not_granted',
                'scopes asked for' => 'openid',
                'claims asked for by name' => 'email',
            ],
            $this->observation('Decision'),
        );
    }

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
     * Decision 0006, Decision 0011
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
        static::assertStringContainsString('beffroi_interaction_authorize', $crawler->filter('body')->text());
    }

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
            'authorization_code refresh_token client_credentials urn:ietf:params:oauth:grant-type:device_code urn:openid:params:grant-type:ciba urn:ietf:params:oauth:grant-type:token-exchange urn:ietf:params:oauth:grant-type:jwt-bearer',
            $served['grant_types_supported'],
        );
        static::assertSame('S256', $served['code_challenge_methods_supported']);
    }

    /**
     * Architecture §4.3
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
     * RFC 6749 §5.1
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
     * RFC 8628 §3.2, §3.3.1
     */
    #[Test]
    public function theAnswerOfTheDeviceAuthorizationEndpointIsShownWithoutItsCodes(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('POST', '/device_authorization', [
            'client_id' => 'appliance-public-app',
            'scope' => 'openid profile',
        ]);

        // Then
        $body = $this->observation('Answer')['body'];
        static::assertStringContainsString('device_code=(present, withheld)', $body);
        static::assertStringContainsString('user_code=(present, withheld)', $body);
        static::assertStringContainsString('verification_uri_complete=(present, withheld)', $body);
        static::assertStringContainsString('verification_uri="https://op.test/device"', $body);
    }

    /**
     * CIBA Core §7.3
     */
    #[Test]
    public function theAnswerOfTheBackchannelAuthenticationEndpointIsShownWithoutItsIdentifier(): void
    {
        // Given
        self::user('alice');
        $this->browser->enableProfiler();

        // When
        $this->browser->request(
            'POST',
            '/backchannel_authentication',
            [
                'scope' => 'openid profile',
                'login_hint' => 'alice-subject',
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('terminal-app:terminal-secret-of-at-least-32-characters'),
            ],
        );

        // Then
        $body = $this->observation('Answer')['body'];
        static::assertStringContainsString('auth_req_id=(present, withheld)', $body);
        static::assertStringContainsString('expires_in=300', $body);
    }

    /**
     * RFC 9126 §2.2, §7.1
     */
    #[Test]
    public function theAnswerOfThePushedAuthorizationRequestEndpointIsShownWithoutItsReference(): void
    {
        // Given
        $this->browser->enableProfiler();

        // When
        $this->browser->request('POST', '/par', self::authorizationParameters());

        // Then
        $body = $this->observation('Answer')['body'];
        static::assertStringContainsString('request_uri=(present, withheld)', $body);
        static::assertStringContainsString('expires_in=60', $body);
    }

    /**
     * RFC 9126 §4
     */
    #[Test]
    public function theQueryOfAPushedRequestIsShownWithoutItsReference(): void
    {
        // Given
        $this->browser->request('POST', '/par', self::authorizationParameters());
        $requestUri = self::string(self::json($this->browser->getResponse())['request_uri'] ?? null);
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'native-app',
            'request_uri' => $requestUri,
        ]);

        // Then
        static::assertSame(
            "client_id=\"native-app\"\nrequest_uri=(present, withheld)",
            $this->observation('Authorization request')['the query the browser carried'],
        );
    }

    /**
     * OIDC Core §2, Decision 0011
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
