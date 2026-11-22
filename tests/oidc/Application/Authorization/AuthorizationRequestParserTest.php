<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use function array_filter;
use function array_merge;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\Display;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\UnsupportedResponseModeException;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\ChallengeMethods;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\ServedModes;
use Beffroi\Oidc\Tests\Fixture\WiredModes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

final class AuthorizationRequestParserTest extends TestCase
{
    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * RFC 7638 §3.1
     */
    private const string THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    /**
     * RFC 7515 §7.1
     */
    private const string ID_TOKEN = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2lkLmFjbWUuZXhhbXBsZSJ9.c2lnbmF0dXJl';

    private Tenant $tenant;

    private Client $client;

    private InMemoryClientRepository $clients;

    private AuthorizationRequestParser $parser;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clients = new InMemoryClientRepository();
        $this->client = Clients::confidential(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            resources: Clients::resources(),
            authorizationDetailsTypes: Clients::authorizationDetailsTypes(),
        );
        $this->clients->save($this->client);
        $this->clients->save(Clients::confidential(
            Fixtures::tenant('other', 'https://id.other.example'),
            new FakePasswordHasher()->hash(Clients::SECRET),
            clientId: 'foreign',
        ));
        $this->parser = new AuthorizationRequestParser(
            $this->clients,
            ServedModes::queryAndFormPost(),
            AuthorizationDetailTypes::served(),
            ChallengeMethods::s256(),
        );
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itReadsACompleteRequest(): void
    {
        // When
        $request = $this->parse([
            'nonce' => 'n-0S6_WzA2Mj',
            'prompt' => 'login consent',
            'max_age' => '86400',
            'login_hint' => 'alice@acme.example',
            'ui_locales' => 'fr-CA fr en',
            'acr_values' => 'urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze',
            'display' => 'page',
            'id_token_hint' => self::ID_TOKEN,
            'claims' => '{"id_token": {"auth_time": {"essential": true}}}',
            'response_mode' => 'query',
            'resource' => Clients::CALENDAR,
        ]);

        // Then
        static::assertSame($this->client, $request->client);
        static::assertSame('https://demo.localhost/login/check', (string) $request->redirectUri);
        static::assertEquals([Scope::openid(), new Scope('profile')], $request->scopes->all);
        static::assertSame(self::CHALLENGE, $request->codeChallenge?->value);
        static::assertSame('S256', $request->codeChallenge->method->name());
        static::assertSame('af0ifjsldkj', $request->state);
        static::assertSame('n-0S6_WzA2Mj', $request->nonce);
        static::assertSame([Prompt::Login, Prompt::Consent], $request->prompts);
        static::assertSame(86400, $request->maxAge);
        static::assertSame('alice@acme.example', $request->loginHint);
        static::assertSame(['fr-CA', 'fr', 'en'], $request->uiLocales);
        static::assertSame(['urn:mace:incommon:iap:silver', 'urn:mace:incommon:iap:bronze'], $request->acrValues);
        static::assertSame(Display::Page, $request->display);
        static::assertSame(self::ID_TOKEN, $request->idTokenHint);
        static::assertEquals(
            [
                'auth_time' => new ClaimRequest(true),
            ],
            $request->claims?->idToken,
        );
        static::assertSame('query', $request->responseMode);
        static::assertSame([Clients::CALENDAR], $request->resources?->values());
    }

    /**
     * RFC 6749 §4.1.1, OIDC Core §3.1.2.1, RFC 7636 §4.3, decision 0006
     */
    #[Test]
    public function itReadsAMinimalRequest(): void
    {
        // When
        $request = $this->parse([
            'state' => '',
        ]);

        // Then
        static::assertNull($request->state);
        static::assertNull($request->nonce);
        static::assertSame([], $request->prompts);
        static::assertNull($request->maxAge);
        static::assertNull($request->loginHint);
        static::assertSame([], $request->uiLocales);
        static::assertSame([], $request->acrValues);
        static::assertNull($request->display);
        static::assertNull($request->idTokenHint);
        static::assertNull($request->claims);
        static::assertSame('query', $request->responseMode);
        static::assertNull($request->resources);
        static::assertNull($request->authorizationDetails);
    }

    /**
     * RFC 8707 §2.1
     */
    #[Test]
    public function itReadsTheResourcesTheRequestNamesSeveralTimes(): void
    {
        // When
        $request = $this->parse([
            'resource' => [Clients::CALENDAR, Clients::CONTACTS],
        ]);

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $request->resources?->values());
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    #[DataProvider('provideResourcesThatAreNotAbsoluteUris')]
    public function itRefusesAResourceThatIsNotAnAbsoluteUri(mixed $resource): void
    {
        // When
        try {
            $this->parse([
                'resource' => $resource,
            ]);
            static::fail('The request should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_target', $exception->error);
            static::assertSame(
                'The resource parameter is an absolute URI without a fragment component (RFC 8707 section 2).',
                $exception->errorDescription,
            );
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideResourcesThatAreNotAbsoluteUris(): iterable
    {
        yield 'a relative URI' => ['/calendar'];
        yield 'a fragment' => ['https://cal.example.com/#today'];
        yield 'one of several' => [[Clients::CALENDAR, 'cal.example.com']];
    }

    /**
     * RFC 9396 §2
     */
    #[Test]
    public function itReadsTheAuthorizationDetailsTheRequestAsksFor(): void
    {
        // When
        $request = $this->parse([
            'authorization_details' => AuthorizationDetailTypes::parameter('acct-4711', ['read', 'write']),
        ]);

        // Then
        static::assertTrue($request->authorizationDetails?->equals(AuthorizationDetailTypes::details('acct-4711', ['read', 'write'])));
    }

    /**
     * RFC 9396 §5
     */
    #[Test]
    #[DataProvider('provideAuthorizationDetailsThatAreNotOne')]
    public function itRefusesAnAuthorizationDetailsThatIsNotOne(string $authorizationDetails): void
    {
        // When
        try {
            $this->parse([
                'authorization_details' => $authorizationDetails,
            ]);
            static::fail('The request should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_authorization_details', $exception->error);
            static::assertSame(
                'The authorization_details parameter is a JSON array of objects, each naming in type an authorization detail type this provider serves and holding what that type accepts (RFC 9396 section 2).',
                $exception->errorDescription,
            );
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAuthorizationDetailsThatAreNotOne(): iterable
    {
        yield 'not JSON' => ['[{'];
        yield 'a JSON object' => ['{"type":"account_information","account":"acct-4711"}'];
        yield 'an empty array' => ['[]'];
        yield 'an element naming no type' => ['[{"account":"acct-4711"}]'];
        yield 'a type nobody serves' => ['[{"type":"payment_initiation","account":"acct-4711"}]'];
        yield 'a detail its own type refuses' => ['[{"type":"account_information","actions":["read"]}]'];
    }

    /**
     * RFC 9396 §11
     */
    #[Test]
    public function itRefusesAnAuthorizationDetailTypeTheClientIsNotRegisteredFor(): void
    {
        // Given
        $this->clients->save(Clients::confidential(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            clientId: 'no-details',
        ));

        // When
        try {
            $this->parse([
                'client_id' => 'no-details',
                'authorization_details' => AuthorizationDetailTypes::parameter(),
            ]);
            static::fail('The request should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_authorization_details', $exception->error);
            static::assertSame(
                'The requested authorization detail type is not one this client is registered for (RFC 9396 section 11).',
                $exception->errorDescription,
            );
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * RFC 8707 §2.1
     */
    #[Test]
    public function itRefusesAResourceTheClientIsNotRegisteredFor(): void
    {
        // When
        try {
            $this->parse([
                'resource' => 'https://files.example.com/',
            ]);
            static::fail('The request should have been refused.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_target', $exception->error);
            static::assertSame(
                'The requested resource is not one this client is registered for (RFC 8707 section 2).',
                $exception->errorDescription,
            );
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * RFC 6749 §3.1
     */
    #[Test]
    public function itRefusesAResourceThatIsNotTextAtAll(): void
    {
        // When
        try {
            $this->parse([
                'resource' => [
                    'one' => Clients::CALENDAR,
                ],
            ]);
            static::fail('The request should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertSame('The resource parameter must be a string or a list of strings.', $exception->errorDescription);
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * OAuth 2.0 Form Post Response Mode §2
     */
    #[Test]
    public function itReadsTheFormPostResponseMode(): void
    {
        // When
        $request = $this->parse([
            'response_mode' => 'form_post',
        ]);

        // Then
        static::assertSame(ServedModes::FORM_POST, $request->responseMode);
    }

    /**
     * RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6
     */
    #[Test]
    public function theRedirectTargetOfTheFirstStageCarriesTheRequestedMode(): void
    {
        // When
        $target = $this->parser->redirectTarget($this->tenant, self::parameters([
            'response_mode' => 'form_post',
        ]));

        // Then
        static::assertSame(ServedModes::FORM_POST, $target->responseMode);
    }

    /**
     * JARM §2.1
     */
    #[Test]
    public function itResolvesTheJwtResponseModeToTheSignedQuery(): void
    {
        // Given
        $parser = new AuthorizationRequestParser($this->clients, ServedModes::signedToo(), AuthorizationDetailTypes::served(), ChallengeMethods::s256());
        $parameters = self::parameters([
            'response_mode' => 'jwt',
        ]);

        // When
        $request = $parser->parse($parser->redirectTarget($this->tenant, $parameters), $parameters);

        // Then
        static::assertSame(ServedModes::SIGNED_QUERY, $request->responseMode);
    }

    /**
     * JARM §2.1
     */
    #[Test]
    public function itReadsTheSignedFormPostResponseMode(): void
    {
        // Given
        $parser = new AuthorizationRequestParser($this->clients, ServedModes::signedToo(), AuthorizationDetailTypes::served(), ChallengeMethods::s256());
        $parameters = self::parameters([
            'response_mode' => 'form_post.jwt',
        ]);

        // When
        $request = $parser->parse($parser->redirectTarget($this->tenant, $parameters), $parameters);

        // Then
        static::assertSame(ServedModes::SIGNED_FORM_POST, $request->responseMode);
    }

    #[Test]
    public function theJwtResponseModeIsRefusedWhereNoSignedModeIsWired(): void
    {
        // Given
        $parameters = self::parameters([
            'response_mode' => 'jwt',
        ]);

        // Then
        $this->expectException(UnsupportedResponseModeException::class);
        $this->expectExceptionMessageIs('unsupported_response_mode: The requested response mode is not supported.');

        // When
        $this->parser->parse($this->parser->redirectTarget($this->tenant, $parameters), $parameters);
    }

    #[Test]
    public function aModeTheIntegrationDidNotWireIsRefused(): void
    {
        // Given
        $parser = new AuthorizationRequestParser($this->clients, ServedModes::queryOnly(), AuthorizationDetailTypes::served(), ChallengeMethods::s256());
        $parameters = self::parameters([
            'response_mode' => 'form_post',
        ]);

        // Then
        $this->expectException(UnsupportedResponseModeException::class);
        $this->expectExceptionMessageIs('unsupported_response_mode: The requested response mode is not supported.');

        // When
        $parser->parse($parser->redirectTarget($this->tenant, $parameters), $parameters);
    }

    /**
     * Multiple Response Type Encoding Practices §2.1
     */
    #[Test]
    public function aModeTheIntegrationDidNotWireIsRefusedInTheDefaultMode(): void
    {
        // When
        $target = $this->parser->redirectTarget($this->tenant, self::parameters([
            'response_mode' => 'fragment',
        ]));

        // Then
        static::assertSame(ServedModes::QUERY, $target->responseMode);
    }

    #[Test]
    public function aDeploymentThatWiresNoQueryFallsBackToAModeItServes(): void
    {
        // Given
        $parser = new AuthorizationRequestParser(
            $this->clients,
            WiredModes::of([ServedModes::FORM_POST]),
            AuthorizationDetailTypes::served(),
            ChallengeMethods::s256(),
        );

        // When
        $target = $parser->redirectTarget($this->tenant, self::parameters([
            'response_mode' => 'fragment',
        ]));

        // Then
        static::assertSame(ServedModes::FORM_POST, $target->responseMode);
    }

    /**
     * Multiple Response Type Encoding Practices §2.1
     */
    #[Test]
    public function aRequestThatAsksForNoModeFallsBackToAModeItServes(): void
    {
        // Given
        $parser = new AuthorizationRequestParser(
            $this->clients,
            WiredModes::of([ServedModes::FORM_POST]),
            AuthorizationDetailTypes::served(),
            ChallengeMethods::s256(),
        );

        // When
        $target = $parser->redirectTarget($this->tenant, self::parameters([]));

        // Then
        static::assertSame(ServedModes::FORM_POST, $target->responseMode);
    }

    /**
     * RFC 6749 §3.1
     */
    #[Test]
    public function itIgnoresUnknownParameters(): void
    {
        // When
        $request = $this->parse([
            'foo' => 'bar',
            'whatever' => ['a', 'b'],
        ]);

        // Then
        static::assertSame($this->client, $request->client);
    }

    /**
     * RFC 6749 §3.1
     */
    #[Test]
    public function itTreatsAnEmptyParameterAsOmitted(): void
    {
        // When
        $request = $this->parse([
            'nonce' => '',
            'prompt' => '',
            'claims' => '',
            'request' => '',
            'request_uri' => '',
        ]);

        // Then
        static::assertNull($request->nonce);
        static::assertSame([], $request->prompts);
        static::assertNull($request->claims);
    }

    /**
     * RFC 6749 §3.3, OIDC Core §3.1.2.1
     */
    #[Test]
    public function itReadsScopesOnceEach(): void
    {
        // When
        $request = $this->parse([
            'scope' => 'email openid email profile',
        ]);

        // Then
        static::assertEquals([new Scope('email'), Scope::openid(), new Scope('profile')], $request->scopes->all);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function itReadsAZeroMaxAge(): void
    {
        // When
        $request = $this->parse([
            'max_age' => '0',
        ]);

        // Then
        static::assertSame(0, $request->maxAge);
    }

    /**
     * OIDC Core §3.1.2.1
     *
     * @param list<Prompt> $prompts
     */
    #[Test]
    #[DataProvider('providePrompts')]
    public function itReadsThePromptValues(string $value, array $prompts): void
    {
        // When
        $request = $this->parse([
            'prompt' => $value,
        ]);

        // Then
        static::assertSame($prompts, $request->prompts);
    }

    /**
     * @return iterable<string, array{string, list<Prompt>}>
     */
    public static function providePrompts(): iterable
    {
        yield 'none alone' => ['none', [Prompt::None]];
        yield 'a value repeated' => ['select_account consent select_account', [Prompt::SelectAccount, Prompt::Consent]];
    }

    /**
     * RFC 6749 §4.1.2.1, RFC 9700 §4.1, OIDC Core §3.1.2.1
     *
     * @param array<string, mixed> $overrides
     */
    #[Test]
    #[DataProvider('provideRequestsShownToTheUser')]
    public function itShowsTheErrorWhenTheClientOrTheRedirectUriIsNotEstablished(array $overrides, string $description): void
    {
        // When
        try {
            $this->parser->redirectTarget($this->tenant, self::parameters($overrides));
            static::fail('The request should have been rejected.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_request', $exception->error);
            static::assertSame($description, $exception->errorDescription);
            static::assertFalse($exception->redirectable);
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideRequestsShownToTheUser(): iterable
    {
        yield 'no client_id' => [
            [
                'client_id' => null,
            ],
            'The client_id parameter is missing.',
        ];
        yield 'empty client_id' => [
            [
                'client_id' => '',
            ],
            'The client_id parameter is missing.',
        ];
        yield 'unknown client' => [
            [
                'client_id' => 'nobody',
            ],
            'The client is unknown.',
        ];
        yield 'client of another tenant' => [
            [
                'client_id' => 'foreign',
            ],
            'The client is unknown.',
        ];
        yield 'client_id differing by case (RFC 6749 appendix A.1, exact match)' => [
            [
                'client_id' => 'OIDC-DEMO',
            ],
            'The client is unknown.',
        ];
        yield 'no redirect_uri' => [
            [
                'redirect_uri' => null,
            ],
            'The redirect_uri parameter is missing.',
        ];
        yield 'unregistered redirect_uri' => [
            [
                'redirect_uri' => 'https://attacker.example/login/check',
            ],
            'The redirect_uri parameter is not registered for this client.',
        ];
        yield 'redirect_uri with a trailing slash (RFC 6749 §3.1.2.3, byte for byte)' => [
            [
                'redirect_uri' => 'https://demo.localhost/login/check/',
            ],
            'The redirect_uri parameter is not registered for this client.',
        ];
        yield 'redirect_uri with a query (RFC 9700 §4.1.3, no pattern)' => [
            [
                'redirect_uri' => 'https://demo.localhost/login/check?x=1',
            ],
            'The redirect_uri parameter is not registered for this client.',
        ];
        yield 'redirect_uri with a different scheme' => [
            [
                'redirect_uri' => 'http://demo.localhost/login/check',
            ],
            'The redirect_uri parameter is not registered for this client.',
        ];
        yield 'redirect_uri differing by case' => [
            [
                'redirect_uri' => 'https://demo.localhost/Login/Check',
            ],
            'The redirect_uri parameter is not registered for this client.',
        ];
        yield 'redirect_uri of the post-logout list' => [
            [
                'redirect_uri' => 'https://demo.localhost/',
            ],
            'The redirect_uri parameter is not registered for this client.',
        ];
        yield 'state beyond ASCII (RFC 6749 appendix A.5)' => [
            [
                'state' => 'état',
            ],
            'The state parameter must be printable ASCII text (RFC 6749 appendix A.5).',
        ];
        yield 'state with a line break' => [
            [
                'state' => "a\nb",
            ],
            'The state parameter must be printable ASCII text (RFC 6749 appendix A.5).',
        ];
        yield 'state with a trailing newline' => [
            [
                'state' => "af0ifjsldkj\n",
            ],
            'The state parameter must be printable ASCII text (RFC 6749 appendix A.5).',
        ];
    }

    /**
     * RFC 6749 §3.1
     */
    #[Test]
    #[DataProvider('provideParametersOfTheFirstStage')]
    public function itRefusesARepeatedParameterOfTheFirstStage(string $name): void
    {
        // Given
        $parameters = self::parameters([
            $name => ['a', 'b'],
        ]);

        // When
        try {
            $this->parser->redirectTarget($this->tenant, $parameters);
            static::fail(sprintf('A repeated %s should have been rejected.', $name));
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_request', $exception->error);
            static::assertSame(sprintf('The %s parameter must be a single string.', $name), $exception->errorDescription);
            static::assertFalse($exception->redirectable);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideParametersOfTheFirstStage(): iterable
    {
        foreach (['client_id', 'redirect_uri', 'state'] as $name) {
            yield $name => [$name];
        }
    }

    /**
     * RFC 6749 §3.1
     */
    #[Test]
    #[DataProvider('provideParametersOfTheSecondStage')]
    public function itRefusesARepeatedParameterOfTheSecondStage(string $name): void
    {
        // Given
        $parameters = self::parameters([
            $name => ['a', 'b'],
        ]);
        $target = $this->parser->redirectTarget($this->tenant, $parameters);

        // When
        try {
            $this->parser->parse($target, $parameters);
            static::fail(sprintf('A repeated %s should have been rejected.', $name));
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame('invalid_request', $exception->error);
            static::assertSame(sprintf('The %s parameter must be a single string.', $name), $exception->errorDescription);
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideParametersOfTheSecondStage(): iterable
    {
        foreach ([
            'response_type',
            'response_mode',
            'scope',
            'code_challenge',
            'code_challenge_method',
            'nonce',
            'prompt',
            'max_age',
            'login_hint',
            'ui_locales',
            'acr_values',
            'display',
            'id_token_hint',
            'claims',
        ] as $name) {
            yield $name => [$name];
        }
    }

    /**
     * RFC 9101 §6.1
     */
    #[Test]
    #[DataProvider('provideRequestObjectParameters')]
    public function aRequestObjectReachingTheParserIsAFaultOfTheIntegration(string $name): void
    {
        // Given
        $parameters = self::parameters([
            $name => self::ID_TOKEN,
        ]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('was wired without the resolver');

        // When
        $this->parser->redirectTarget($this->tenant, $parameters);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRequestObjectParameters(): iterable
    {
        yield 'request' => ['request'];
        yield 'request_uri' => ['request_uri'];
    }

    /**
     * RFC 6749 §4.1.2.1
     */
    #[Test]
    public function itEstablishesTheTargetBeforeReadingAnythingElse(): void
    {
        // When
        $target = $this->parser->redirectTarget($this->tenant, [
            'client_id' => 'oidc-demo',
            'redirect_uri' => 'https://demo.localhost/login/check',
            'state' => 'af0ifjsldkj',
            'response_type' => 'token',
            'scope' => ['not', 'a', 'string'],
        ]);

        // Then
        static::assertSame($this->client, $target->client);
        static::assertSame('https://demo.localhost/login/check', (string) $target->redirectUri);
        static::assertSame('af0ifjsldkj', $target->state);
    }

    /**
     * RFC 6749 §4.1.1
     */
    #[Test]
    public function theTargetCarriesNoStateWhenTheRequestHadNone(): void
    {
        // When
        $target = $this->parser->redirectTarget($this->tenant, self::parameters([
            'state' => null,
        ]));

        // Then
        static::assertNull($target->state);
    }

    /**
     * RFC 6749 §4.1.2.1, OIDC Core §3.1.2.1, §3.1.2.2, §3.1.2.6, RFC 7636 §4.3
     *
     * @param array<string, mixed> $overrides
     */
    #[Test]
    #[DataProvider('provideRequestsSentBackToTheClient')]
    public function itRedirectsTheErrorOnceTheTargetIsEstablished(array $overrides, string $error, string $description): void
    {
        // Given
        $parameters = self::parameters($overrides);
        $target = $this->parser->redirectTarget($this->tenant, $parameters);

        // When
        try {
            $this->parser->parse($target, $parameters);
            static::fail('The request should have been rejected.');
        } catch (OAuth2Exception $exception) {
            // Then
            static::assertSame($error, $exception->error);
            static::assertSame($description, $exception->errorDescription);
            static::assertTrue($exception->redirectable);
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function provideRequestsSentBackToTheClient(): iterable
    {
        yield 'no response_type (RFC 6749 §4.1.1)' => [
            [
                'response_type' => null,
            ],
            'invalid_request',
            'The response_type parameter is missing.',
        ];
        yield 'implicit flow (OIDC Core §3.2, decision 0006)' => [
            [
                'response_type' => 'id_token token',
            ],
            'unsupported_response_type',
            'Only the code response type is supported.',
        ];
        yield 'hybrid flow (OIDC Core §3.3)' => [
            [
                'response_type' => 'code id_token',
            ],
            'unsupported_response_type',
            'Only the code response type is supported.',
        ];
        yield 'token response type (RFC 6749 §4.2)' => [
            [
                'response_type' => 'token',
            ],
            'unsupported_response_type',
            'Only the code response type is supported.',
        ];
        yield 'response_type in capitals' => [
            [
                'response_type' => 'CODE',
            ],
            'unsupported_response_type',
            'Only the code response type is supported.',
        ];
        yield 'fragment response mode (Multiple Response Type Encoding Practices §2.1)' => [
            [
                'response_mode' => 'fragment',
            ],
            'unsupported_response_mode',
            'The requested response mode is not supported.',
        ];
        yield 'response mode of no specification' => [
            [
                'response_mode' => 'web_message',
            ],
            'unsupported_response_mode',
            'The requested response mode is not supported.',
        ];
        yield 'response mode in capitals' => [
            [
                'response_mode' => 'FORM_POST',
            ],
            'unsupported_response_mode',
            'The requested response mode is not supported.',
        ];
        yield 'no scope (OIDC Core §3.1.2.1)' => [
            [
                'scope' => null,
            ],
            'invalid_request',
            'The scope parameter is missing.',
        ];
        yield 'scope without openid (OIDC Core §3.1.2.2 step 3)' => [
            [
                'scope' => 'profile email',
            ],
            'invalid_scope',
            'The scope parameter must contain openid (OIDC Core section 3.1.2.1).',
        ];
        yield 'scope with two spaces (RFC 6749 §3.3)' => [
            [
                'scope' => 'openid  profile',
            ],
            'invalid_scope',
            'The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).',
        ];
        yield 'scope with a trailing space' => [
            [
                'scope' => 'openid ',
            ],
            'invalid_scope',
            'The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).',
        ];
        yield 'scope with a double quote' => [
            [
                'scope' => 'openid "profile"',
            ],
            'invalid_scope',
            'The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).',
        ];
        yield 'scope not allowed to the client (RFC 6749 §4.1.2.1)' => [
            [
                'scope' => 'openid address',
            ],
            'invalid_scope',
            'The requested scope is not allowed for this client.',
        ];
        yield 'scope differing by case' => [
            [
                'scope' => 'openid Profile',
            ],
            'invalid_scope',
            'The requested scope is not allowed for this client.',
        ];
        yield 'no code_challenge (RFC 7636 §4.4.1)' => [
            [
                'code_challenge' => null,
            ],
            'invalid_request',
            'The code_challenge parameter is missing (RFC 7636 section 4.3).',
        ];
        yield 'no code_challenge_method, which RFC 7636 §4.3 would read as plain' => [
            [
                'code_challenge_method' => null,
            ],
            'invalid_request',
            'The code_challenge_method parameter must be S256 (RFC 7636 section 4.3).',
        ];
        yield 'plain code_challenge_method (decision 0006)' => [
            [
                'code_challenge_method' => 'plain',
            ],
            'invalid_request',
            'The code_challenge_method parameter must be S256 (RFC 7636 section 4.3).',
        ];
        yield 'code_challenge_method in lower case' => [
            [
                'code_challenge_method' => 's256',
            ],
            'invalid_request',
            'The code_challenge_method parameter must be S256 (RFC 7636 section 4.3).',
        ];
        yield 'code_challenge too short (RFC 7636 §4.2)' => [
            [
                'code_challenge' => str_repeat('a', 42),
            ],
            'invalid_request',
            'The code_challenge parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.2).',
        ];
        yield 'code_challenge with base64 padding' => [
            [
                'code_challenge' => str_repeat('a', 43) . '=',
            ],
            'invalid_request',
            'The code_challenge parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.2).',
        ];
        yield 'nonce with a control character' => [
            [
                'nonce' => "n-0S6\x00WzA2Mj",
            ],
            'invalid_request',
            'The nonce parameter must be text without control characters.',
        ];
        yield 'nonce that is not UTF-8' => [
            [
                'nonce' => "\xff\xfe",
            ],
            'invalid_request',
            'The nonce parameter must be text without control characters.',
        ];
        yield 'unknown prompt value' => [
            [
                'prompt' => 'create',
            ],
            'invalid_request',
            'The prompt parameter is not a space-separated list of none, login, consent or select_account.',
        ];
        yield 'prompt in capitals (case sensitive)' => [
            [
                'prompt' => 'Login',
            ],
            'invalid_request',
            'The prompt parameter is not a space-separated list of none, login, consent or select_account.',
        ];
        yield 'prompt with two spaces' => [
            [
                'prompt' => 'login  consent',
            ],
            'invalid_request',
            'The prompt parameter is not a space-separated list of none, login, consent or select_account.',
        ];
        yield 'prompt none with another value (OIDC Core §3.1.2.1)' => [
            [
                'prompt' => 'none login',
            ],
            'invalid_request',
            'The prompt value none cannot be combined with another value (OIDC Core section 3.1.2.1).',
        ];
        yield 'prompt none after another value' => [
            [
                'prompt' => 'consent none',
            ],
            'invalid_request',
            'The prompt value none cannot be combined with another value (OIDC Core section 3.1.2.1).',
        ];
        yield 'negative max_age' => [
            [
                'max_age' => '-1',
            ],
            'invalid_request',
            'The max_age parameter must be a non-negative integer.',
        ];
        yield 'decimal max_age' => [
            [
                'max_age' => '1.5',
            ],
            'invalid_request',
            'The max_age parameter must be a non-negative integer.',
        ];
        yield 'max_age with a leading zero' => [
            [
                'max_age' => '01',
            ],
            'invalid_request',
            'The max_age parameter must be a non-negative integer.',
        ];
        yield 'max_age with a sign' => [
            [
                'max_age' => '+1',
            ],
            'invalid_request',
            'The max_age parameter must be a non-negative integer.',
        ];
        yield 'max_age beyond an integer' => [
            [
                'max_age' => '1000000000000000000',
            ],
            'invalid_request',
            'The max_age parameter must be a non-negative integer.',
        ];
        yield 'max_age that is not a number' => [
            [
                'max_age' => 'yesterday',
            ],
            'invalid_request',
            'The max_age parameter must be a non-negative integer.',
        ];
        yield 'login_hint with a control character' => [
            [
                'login_hint' => "alice\r\n@acme.example",
            ],
            'invalid_request',
            'The login_hint parameter must be text without control characters.',
        ];
        yield 'login_hint with a trailing newline' => [
            [
                'login_hint' => "alice@acme.example\n",
            ],
            'invalid_request',
            'The login_hint parameter must be text without control characters.',
        ];
        yield 'max_age with a trailing newline' => [
            [
                'max_age' => "60\n",
            ],
            'invalid_request',
            'The max_age parameter must be a non-negative integer.',
        ];
        yield 'ui_locales that is not a language tag' => [
            [
                'ui_locales' => 'fr_FR',
            ],
            'invalid_request',
            'The ui_locales parameter must be a space-separated list of language tags.',
        ];
        yield 'ui_locales with two spaces' => [
            [
                'ui_locales' => 'fr  en',
            ],
            'invalid_request',
            'The ui_locales parameter must be a space-separated list of language tags.',
        ];
        yield 'ui_locales with a subtag too long' => [
            [
                'ui_locales' => 'en-abcdefghi',
            ],
            'invalid_request',
            'The ui_locales parameter must be a space-separated list of language tags.',
        ];
        yield 'acr_values with a control character' => [
            [
                'acr_values' => "urn:a\tb",
            ],
            'invalid_request',
            'The acr_values parameter must be a space-separated list of printable ASCII values.',
        ];
        yield 'acr_values beyond ASCII' => [
            [
                'acr_values' => 'argenté',
            ],
            'invalid_request',
            'The acr_values parameter must be a space-separated list of printable ASCII values.',
        ];
        yield 'acr_values with a trailing newline' => [
            [
                'acr_values' => "urn:a\n",
            ],
            'invalid_request',
            'The acr_values parameter must be a space-separated list of printable ASCII values.',
        ];
        yield 'unknown display value' => [
            [
                'display' => 'modal',
            ],
            'invalid_request',
            'The display parameter is not one of page, popup, touch or wap.',
        ];
        yield 'display in capitals' => [
            [
                'display' => 'Page',
            ],
            'invalid_request',
            'The display parameter is not one of page, popup, touch or wap.',
        ];
        yield 'id_token_hint that is not a JWT' => [
            [
                'id_token_hint' => 'not-a-token',
            ],
            'invalid_request',
            'The id_token_hint parameter is not a signed compact JWT.',
        ];
        yield 'id_token_hint without a signature (RFC 7515 §7.1, OIDC Core §2)' => [
            [
                'id_token_hint' => 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.',
            ],
            'invalid_request',
            'The id_token_hint parameter is not a signed compact JWT.',
        ];
        yield 'id_token_hint with base64 padding' => [
            [
                'id_token_hint' => 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln=',
            ],
            'invalid_request',
            'The id_token_hint parameter is not a signed compact JWT.',
        ];
        yield 'claims that is not JSON' => [
            [
                'claims' => '{',
            ],
            'invalid_request',
            'The claims parameter is not a claims request (OIDC Core section 5.5).',
        ];
        yield 'claims that is not an object' => [
            [
                'claims' => '["email"]',
            ],
            'invalid_request',
            'The claims parameter is not a claims request (OIDC Core section 5.5).',
        ];
        yield 'claims with essential as a string' => [
            [
                'claims' => '{"userinfo": {"email": {"essential": "true"}}}',
            ],
            'invalid_request',
            'The claims parameter is not a claims request (OIDC Core section 5.5).',
        ];
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    #[DataProvider('provideDisplays')]
    public function itReadsEveryDisplayValue(string $value, Display $display): void
    {
        // When
        $request = $this->parse([
            'display' => $value,
        ]);

        // Then
        static::assertSame($display, $request->display);
    }

    /**
     * @return iterable<string, array{string, Display}>
     */
    public static function provideDisplays(): iterable
    {
        yield 'page' => ['page', Display::Page];
        yield 'popup' => ['popup', Display::Popup];
        yield 'touch' => ['touch', Display::Touch];
        yield 'wap' => ['wap', Display::Wap];
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function parse(array $overrides): AuthorizationRequest
    {
        $parameters = self::parameters($overrides);

        return $this->parser->parse($this->parser->redirectTarget($this->tenant, $parameters), $parameters);
    }

    /**
     * RFC 9449 §10
     */
    #[Test]
    public function itReadsTheKeyTheRequestReservesItsCodeFor(): void
    {
        // When
        $request = $this->parse([
            'dpop_jkt' => self::THUMBPRINT,
        ]);

        // Then
        static::assertEquals(new KeyConfirmation(self::THUMBPRINT), $request->dpopKey);
    }

    #[Test]
    public function aRequestThatReservesNothingNamesNoKey(): void
    {
        // When
        $request = $this->parse([]);

        // Then
        static::assertNull($request->dpopKey);
    }

    /**
     * RFC 9449 §10, RFC 7638 §3.1
     */
    #[Test]
    #[DataProvider('provideThumbprintsThatAreNotOnes')]
    public function aKeyThatIsNotNamedByAThumbprintIsRefused(string $thumbprint): void
    {
        // When
        try {
            $this->parse([
                'dpop_jkt' => $thumbprint,
            ]);
            static::fail('A dpop_jkt that is not a thumbprint should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertSame(
                'invalid_request: The dpop_jkt parameter is the JWK thumbprint of a key, the base64url of a SHA-256 (RFC 9449 section 10).',
                $exception->getMessage(),
            );
            static::assertTrue($exception->redirectable, 'the client and the redirect URI are known by then, so the refusal goes back to the client');
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideThumbprintsThatAreNotOnes(): iterable
    {
        yield 'too short' => ['NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X'];
        yield 'too long' => [self::THUMBPRINT . 'a'];
        yield 'not base64url' => ['NzbLsXh8uDCcd+6MNwXF4W/7noWXFZAfHkxZsRGC9Xs'];
        yield 'padded' => ['NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X='];
    }

    /**
     * Decision 0008
     */
    #[Test]
    public function itAcceptsARequestWithoutPkceFromAClientThatDoesNotRequireIt(): void
    {
        // Given
        $this->legacyClient();

        // When
        $request = $this->parse([
            'client_id' => 'legacy',
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]);

        // Then
        static::assertNull($request->codeChallenge);
    }

    /**
     * RFC 9700 §2.1.1
     */
    #[Test]
    public function itKeepsTheChallengeAClientThatDoesNotRequirePkceSends(): void
    {
        // Given
        $this->legacyClient();

        // When
        $request = $this->parse([
            'client_id' => 'legacy',
        ]);

        // Then
        static::assertSame(self::CHALLENGE, $request->codeChallenge?->value);
    }

    /**
     * Decision 0008
     *
     * @param array<string, mixed> $overrides
     */
    #[Test]
    #[DataProvider('provideMalformedPkceOfAClientThatDoesNotRequireIt')]
    public function itRefusesAMalformedChallengeEvenFromAClientThatDoesNotRequirePkce(array $overrides, string $description): void
    {
        // Given
        $this->legacyClient();

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: ' . $description);

        // When
        $this->parse([
            'client_id' => 'legacy',
        ] + $overrides);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedPkceOfAClientThatDoesNotRequireIt(): iterable
    {
        yield 'plain method (decision 0006)' => [
            [
                'code_challenge_method' => 'plain',
            ],
            'The code_challenge_method parameter must be S256 (RFC 7636 section 4.3).',
        ];
        yield 'method without a challenge' => [
            [
                'code_challenge' => null,
            ],
            'The code_challenge parameter is missing (RFC 7636 section 4.3).',
        ];
        yield 'challenge without a method, which RFC 7636 §4.3 would read as plain' => [
            [
                'code_challenge_method' => null,
            ],
            'The code_challenge_method parameter must be S256 (RFC 7636 section 4.3).',
        ];
    }

    /**
     * RFC 9126 §6
     */
    #[Test]
    public function itRefusesAnOrdinaryRequestFromAClientThatMustPushIt(): void
    {
        // Given
        $this->pushingClient();

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The client only starts an authorization request by pushing it (RFC 9126 section 6).');

        // When
        $this->parser->redirectTarget($this->tenant, self::parameters([
            'client_id' => 'fapi-demo',
            'redirect_uri' => 'https://fapi.localhost/login/check',
        ]));
    }

    /**
     * RFC 9126 §6
     */
    #[Test]
    public function itReadsTheRequestOfThatClientOnceItHasBeenPushed(): void
    {
        // Given
        $this->pushingClient();

        // When
        $target = $this->parser->redirectTarget(
            $this->tenant,
            self::parameters([
                'client_id' => 'fapi-demo',
                'redirect_uri' => 'https://fapi.localhost/login/check',
            ]),
            true,
        );

        // Then
        static::assertSame('fapi-demo', $target->client->registration->clientId);
    }

    /**
     * RFC 9101 §10.5, FAPI 2.0 Message Signing §5.3.1
     */
    #[Test]
    public function itRefusesARequestNoSignedObjectCarriedFromAClientThatMustSignIt(): void
    {
        // Given
        $this->signingClient();

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: The client only starts an authorization request with a request object it signed (RFC 9101 section 10.5, require_signed_request_object).');

        // When
        $this->parser->redirectTarget($this->tenant, self::parameters([
            'client_id' => 'jar-client',
            'redirect_uri' => 'https://jar.example/callback',
        ]));
    }

    /**
     * RFC 9101 §10.5
     */
    #[Test]
    public function itReadsTheRequestOfThatClientFromAnObjectItSigned(): void
    {
        // Given
        $this->signingClient();

        // When
        $target = $this->parser->redirectTarget(
            $this->tenant,
            self::parameters([
                'client_id' => 'jar-client',
                'redirect_uri' => 'https://jar.example/callback',
            ]),
            signed: true,
        );

        // Then
        static::assertSame('jar-client', $target->client->registration->clientId);
    }

    /**
     * RFC 9126 §6
     */
    #[Test]
    public function aClientThatDoesNotRequireItStartsAnOrdinaryRequest(): void
    {
        // When
        $target = $this->parser->redirectTarget($this->tenant, self::parameters([]));

        // Then
        static::assertSame('oidc-demo', $target->client->registration->clientId);
    }

    /**
     * RFC 9126 §6
     */
    private function pushingClient(): void
    {
        $this->clients->save(Clients::pushingOnly($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET)));
    }

    /**
     * RFC 9101 §10.5
     */
    private function signingClient(): void
    {
        $this->clients->save(Clients::sendingRequestObjects($this->tenant, requiresSignedRequestObject: true));
    }

    /**
     * Decision 0008
     */
    private function legacyClient(): void
    {
        $this->clients->save(Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), clientId: 'legacy', requiresPkce: false));
    }

    /**
     * OIDC Core §3.1.2.1
     *
     * @param array<string, mixed> $overrides a null value removes the parameter
     *
     * @return array<string, mixed>
     */
    private static function parameters(array $overrides): array
    {
        $parameters = array_merge([
            'response_type' => 'code',
            'scope' => 'openid profile',
            'client_id' => 'oidc-demo',
            'state' => 'af0ifjsldkj',
            'redirect_uri' => 'https://demo.localhost/login/check',
            'code_challenge' => self::CHALLENGE,
            'code_challenge_method' => 'S256',
        ], $overrides);

        return array_filter($parameters, static fn (mixed $value): bool => $value !== null);
    }
}
