<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\EndSession;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\EndSession\EndSessionRequestParser;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeJwsVerifier;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EndSessionRequestParserTest extends TestCase
{
    private const string SID = '01996f5a-1c2e-7b3c-9d4e-5f6a7b8c9d0e';

    private const string ALICE_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.YWxpY2U.c2lnbmF0dXJl';

    private const string LISTED_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.bGlzdGVk.c2lnbmF0dXJl';

    private const string GHOST_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.Z2hvc3Q.c2lnbmF0dXJl';

    private const string FORGED_HINT = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.Zm9yZ2Vk.c2lnbmF0dXJl';

    private Tenant $tenant;

    private Client $client;

    private EndSessionRequestParser $parser;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $clients = new InMemoryClientRepository();
        $clients->save($this->client);
        $clients->save(Clients::public($this->tenant));
        $jws = new FakeJwsVerifier();
        $jws->knows($this->tenant, self::ALICE_HINT, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"oidc-demo","exp":1,"sid":"' . self::SID . '"}');
        $jws->knows($this->tenant, self::LISTED_HINT, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":["ghost","oidc-demo","spa"]}');
        $jws->knows($this->tenant, self::GHOST_HINT, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"ghost"}');
        $this->parser = new EndSessionRequestParser($clients, new IdTokenHintVerifier($jws));
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2: the hint identifies the client by "aud" and the session by
     * "sid"; §3: post_logout_redirect_uri is honoured for that client when registered; "state",
     * "logout_hint" and "ui_locales" are carried as given.
     */
    #[Test]
    public function itReadsARequestWithAHint(): void
    {
        $request = $this->parser->parse($this->tenant, [
            'id_token_hint' => self::ALICE_HINT,
            'post_logout_redirect_uri' => 'https://demo.localhost/',
            'state' => 'af0ifjsldkj',
            'logout_hint' => 'alice@acme.example',
            'ui_locales' => 'fr-CA fr en',
            'unknown' => 'ignored',
        ]);

        static::assertSame($this->client, $request->client);
        static::assertNotNull($request->idTokenHint);
        static::assertSame('alice-subject', (string) $request->idTokenHint->subject);
        static::assertSame(self::SID, $request->idTokenHint->sessionId?->toRfc4122());
        static::assertSame('https://demo.localhost/', (string) $request->postLogoutRedirectUri);
        static::assertSame('af0ifjsldkj', $request->state);
        static::assertSame('alice@acme.example', $request->logoutHint);
        static::assertSame(['fr-CA', 'fr', 'en'], $request->uiLocales);
        static::assertSame('https://demo.localhost/?state=af0ifjsldkj', $request->redirect()?->toUri());
    }

    /**
     * §2: every parameter is optional. A bare logout link is a request that names nobody and redirects
     * nowhere; a parameter without a value is treated as omitted (RFC 6749 §3.1).
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('bareRequests')]
    public function itReadsARequestWithoutParameters(array $parameters): void
    {
        $request = $this->parser->parse($this->tenant, $parameters);

        static::assertSame($this->tenant, $request->tenant);
        static::assertNull($request->client);
        static::assertNull($request->idTokenHint);
        static::assertNull($request->postLogoutRedirectUri);
        static::assertNull($request->state);
        static::assertNull($request->logoutHint);
        static::assertSame([], $request->uiLocales);
        static::assertNull($request->redirect());
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function bareRequests(): iterable
    {
        yield 'nothing' => [[]];
        yield 'empty values' => [[
            'id_token_hint' => '',
            'client_id' => '',
            'post_logout_redirect_uri' => '',
            'state' => '',
            'logout_hint' => '',
            'ui_locales' => '',
        ]];
    }

    /**
     * §2 "aud" is a string or a list: the client is the first audience that is a client of the tenant.
     */
    #[Test]
    public function itFindsTheClientAmongTheAudiencesOfTheHint(): void
    {
        $request = $this->parser->parse($this->tenant, [
            'id_token_hint' => self::LISTED_HINT,
        ]);

        static::assertSame($this->client, $request->client);
    }

    /**
     * §2 "client_id": the client, when the request names it, with or without a hint; with a hint, it
     * must be one of its audiences.
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('clientIds')]
    public function itFindsTheClientByClientId(array $parameters, string $expectedClientId): void
    {
        $request = $this->parser->parse($this->tenant, $parameters);

        static::assertSame($expectedClientId, $request->client?->clientId);
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function clientIds(): iterable
    {
        yield 'alone' => [[
            'client_id' => 'spa',
        ], 'spa'];
        yield 'with a hint naming it' => [[
            'client_id' => 'oidc-demo',
            'id_token_hint' => self::ALICE_HINT,
        ], 'oidc-demo'];
        yield 'with a hint listing it' => [[
            'client_id' => 'spa',
            'id_token_hint' => self::LISTED_HINT,
        ], 'spa'];
    }

    /**
     * §3: a redirect is honoured for a client identified by client_id alone too; the confirmation the
     * handler then requires is what §2 asks for a request without a hint.
     */
    #[Test]
    public function itAcceptsARegisteredRedirectForAClientNamedByClientIdAlone(): void
    {
        $request = $this->parser->parse($this->tenant, [
            'client_id' => 'oidc-demo',
            'post_logout_redirect_uri' => 'https://demo.localhost/',
        ]);

        static::assertSame($this->client, $request->client);
        static::assertNull($request->idTokenHint);
        static::assertSame('https://demo.localhost/', $request->redirect()?->toUri());
    }

    /**
     * §2, §3, §4: a request the provider cannot honour is refused and shown, never redirected. The
     * descriptions are the ones the page shows.
     *
     * @param array<string, mixed> $parameters
     */
    #[Test]
    #[DataProvider('invalidRequests')]
    public function itRefusesAnInvalidRequestWithoutRedirecting(array $parameters, string $description): void
    {
        try {
            $this->parser->parse($this->tenant, $parameters);
            static::fail('The request should have been refused.');
        } catch (InvalidRequestException $exception) {
            static::assertFalse($exception->redirectable);
            static::assertSame($description, $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidRequests(): iterable
    {
        yield 'hint not a JWS' => [[
            'id_token_hint' => 'not-a-jwt',
        ], 'The id_token_hint parameter is not a signed compact JWT.'];
        yield 'hint not issued here' => [[
            'id_token_hint' => self::FORGED_HINT,
        ], 'The id_token_hint parameter is not an ID token issued by this provider.'];
        yield 'hint issued to no client of the tenant' => [[
            'id_token_hint' => self::GHOST_HINT,
        ], 'The id_token_hint parameter is not an ID token issued to a client of this provider.'];
        yield 'client_id not an audience of the hint' => [[
            'id_token_hint' => self::ALICE_HINT,
            'client_id' => 'spa',
        ], 'The client_id parameter is not an audience of the id_token_hint parameter.'];
        yield 'client_id unknown' => [[
            'client_id' => 'ghost',
        ], 'The client is unknown.'];
        yield 'client_id unknown even when the hint lists it' => [[
            'id_token_hint' => self::LISTED_HINT,
            'client_id' => 'ghost',
        ], 'The client is unknown.'];
        yield 'redirect without a client' => [[
            'post_logout_redirect_uri' => 'https://demo.localhost/',
        ], 'The post_logout_redirect_uri parameter requires id_token_hint or client_id to identify the client.'];
        yield 'redirect not registered' => [[
            'id_token_hint' => self::ALICE_HINT,
            'post_logout_redirect_uri' => 'https://demo.localhost/logged-out',
        ], 'The post_logout_redirect_uri parameter is not registered for this client.'];
        yield 'redirect registered for the authorization response only' => [[
            'id_token_hint' => self::ALICE_HINT,
            'post_logout_redirect_uri' => 'https://demo.localhost/login/check',
        ], 'The post_logout_redirect_uri parameter is not registered for this client.'];
        yield 'redirect registered on another client' => [[
            'client_id' => 'spa',
            'post_logout_redirect_uri' => 'https://demo.localhost/',
        ], 'The post_logout_redirect_uri parameter is not registered for this client.'];
        yield 'redirect with a trailing slash more' => [[
            'id_token_hint' => self::ALICE_HINT,
            'post_logout_redirect_uri' => 'https://demo.localhost',
        ], 'The post_logout_redirect_uri parameter is not registered for this client.'];
        yield 'state not printable ASCII' => [[
            'state' => "tab\there",
        ], 'The state parameter must be printable ASCII text (RFC 6749 appendix A.5).'];
        yield 'state with a trailing newline' => [[
            'state' => "af0ifjsldkj\n",
        ], 'The state parameter must be printable ASCII text (RFC 6749 appendix A.5).'];
        yield 'hint with a trailing newline' => [[
            'id_token_hint' => self::ALICE_HINT . "\n",
        ], 'The id_token_hint parameter is not a signed compact JWT.'];
        yield 'ui_locales with a trailing newline' => [[
            'ui_locales' => "fr\n",
        ], 'The ui_locales parameter must be a space-separated list of language tags.'];
        yield 'logout_hint with a control character' => [[
            'logout_hint' => "alice\n",
        ], 'The logout_hint parameter must be text without control characters.'];
        yield 'ui_locales not language tags' => [[
            'ui_locales' => 'fr_FR',
        ], 'The ui_locales parameter must be a space-separated list of language tags.'];
        yield 'repeated id_token_hint' => [[
            'id_token_hint' => [self::ALICE_HINT, self::ALICE_HINT],
        ], 'The id_token_hint parameter must be a single string.'];
        yield 'repeated client_id' => [[
            'client_id' => ['oidc-demo', 'spa'],
        ], 'The client_id parameter must be a single string.'];
        yield 'repeated post_logout_redirect_uri' => [[
            'id_token_hint' => self::ALICE_HINT,
            'post_logout_redirect_uri' => ['https://demo.localhost/', 'https://demo.localhost/'],
        ], 'The post_logout_redirect_uri parameter must be a single string.'];
        yield 'repeated state' => [[
            'state' => ['a', 'b'],
        ], 'The state parameter must be a single string.'];
    }

    /**
     * §2: the hint is verified against the keys of the tenant the request reaches, not any tenant.
     */
    #[Test]
    public function itVerifiesTheHintAgainstTheKeysOfTheTenant(): void
    {
        $this->expectException(InvalidRequestException::class);
        $this->parser->parse(Fixtures::tenant('other', 'https://id.other.example'), [
            'id_token_hint' => self::ALICE_HINT,
        ]);
    }
}
