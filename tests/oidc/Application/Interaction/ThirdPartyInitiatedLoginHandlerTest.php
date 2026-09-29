<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Interaction;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Heidi\Oidc\Application\Interaction\ThirdPartyInitiatedLoginHandler;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §4: a caller names a client of the tenant, and this answers where that client is to be sent
 * the browser, or nothing at all.
 */
final class ThirdPartyInitiatedLoginHandlerTest extends TestCase
{
    private const string CLIENT_ID = 'launched-app';

    private const string INITIATE_LOGIN_URI = 'https://rp.example/start';

    private const string REDIRECT_URI = 'https://rp.example/callback';

    private const string ISSUED_BY_THIS_PROVIDER = '?iss=https%3A%2F%2Fid.acme.example';

    #[Test]
    public function itAnswersTheUriTheNamedClientRegistered(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $handler = self::handlerFor($tenant, Clients::withThirdPartyInitiatedLogin($tenant));

        // When
        $login = $handler->handle($tenant, self::CLIENT_ID) ?? static::fail('There is a login to begin.');

        // Then
        static::assertSame(self::INITIATE_LOGIN_URI, (string) $login->initiateLoginUri);
        static::assertSame($tenant->issuer, $login->issuer);
    }

    /**
     * A client no tenant of this name holds and a client that registered no "initiate_login_uri" are one
     * answer: whoever asks learns which clients exist no more than whoever asks for an interaction that
     * is not theirs learns whose it is.
     *
     * @param callable(Tenant): Client $registered
     */
    #[Test]
    #[DataProvider('provideNothingToBegin')]
    public function thereIsNoLoginToBegin(callable $registered, string $named): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $handler = self::handlerFor($tenant, $registered($tenant));

        // When
        $login = $handler->handle($tenant, $named);

        // Then
        static::assertNull($login);
    }

    /**
     * @return iterable<string, array{callable(Tenant): Client, string}>
     */
    public static function provideNothingToBegin(): iterable
    {
        yield 'a name no client of the tenant holds' => [
            static fn (Tenant $tenant): Client => Clients::withThirdPartyInitiatedLogin($tenant),
            'a-client-nobody-registered',
        ];
        yield 'a client that registered no initiate_login_uri' => [
            static fn (Tenant $tenant): Client => Clients::public($tenant),
            'spa',
        ];
        yield 'no client named at all' => [
            static fn (Tenant $tenant): Client => Clients::withThirdPartyInitiatedLogin($tenant),
            '',
        ];
    }

    /**
     * A client of another tenant is a client this tenant does not hold, whatever it registered.
     */
    #[Test]
    public function aClientOfAnotherTenantIsNoClientOfThisOne(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $elsewhere = Fixtures::tenant('other', 'https://id.other.example');
        $handler = self::handlerFor($elsewhere, Clients::withThirdPartyInitiatedLogin($elsewhere));

        // When
        $login = $handler->handle($tenant, self::CLIENT_ID);

        // Then
        static::assertNull($login);
    }

    /**
     * OIDC Core §4: the hint is optional, and a browser holding no session says nothing of whom to sign
     * in. The redirection happens all the same, since the client is about to ask for whatever login it
     * needs.
     */
    #[Test]
    public function aBrowserWithNoSessionIsSentOnWithNoHint(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $handler = self::handlerFor($tenant, Clients::withThirdPartyInitiatedLogin($tenant));

        // When
        $login = $handler->handle($tenant, self::CLIENT_ID);

        // Then
        static::assertNull($login?->loginHint);
    }

    /**
     * OIDC Core §8: the hint goes through the resolver every other value written for a client goes
     * through, so a client assigned a pairwise identifier is hinted with the one it was handed and never
     * with the identifier the core keeps, which is the one string pairwise exists to withhold.
     */
    #[Test]
    public function aPairwiseClientIsHintedWithTheIdentifierItWasHanded(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $subjects = Subjects::bothKinds();
        $client = Clients::withThirdPartyInitiatedLogin(
            $tenant,
            subjectType: PairwiseSubjectIdentifierResolver::SUBJECT_TYPE,
        );
        $handler = self::handlerFor($tenant, $client, $subjects);

        // When
        $login = $handler->handle($tenant, self::CLIENT_ID, $user);

        // Then
        static::assertNotNull($login?->loginHint);
        static::assertSame($subjects->resolve($user, $client)->value, $login->loginHint->value);
        static::assertNotSame($user->subject->value, $login->loginHint->value);
    }

    /**
     * OIDC Core §8 "public": the kind a client takes by registering none is the identifier the core
     * keeps, so that client is hinted with it.
     */
    #[Test]
    public function aClientTakingThePublicKindIsHintedWithTheSubjectOfTheUser(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $handler = self::handlerFor($tenant, Clients::withThirdPartyInitiatedLogin($tenant));

        // When
        $login = $handler->handle($tenant, self::CLIENT_ID, $user);

        // Then
        static::assertSame($user->subject, $login?->loginHint);
    }

    /**
     * RFC 6749 §3.1.2.3: a landing page the client registered is carried on, as the object the
     * registration holds and not as the string the request carried.
     */
    #[Test]
    public function aLandingPageTheClientRegisteredIsCarried(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $handler = self::handlerFor($tenant, Clients::withThirdPartyInitiatedLogin($tenant));

        // When
        $login = $handler->handle($tenant, self::CLIENT_ID, null, self::REDIRECT_URI);

        // Then
        static::assertSame(self::REDIRECT_URI, $login?->targetLinkUri?->value);
    }

    /**
     * The whole security of the route: nothing of the request reaches the client but the name of a
     * landing page that client registered itself. A caller that names anything else is answered the
     * redirection without one, which is what OIDC Core §4 makes optional.
     */
    #[Test]
    #[DataProvider('provideLandingPagesNobodyRegistered')]
    public function aLandingPageTheClientDidNotRegisterIsLeftOut(string $targetLinkUri): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $handler = self::handlerFor($tenant, Clients::withThirdPartyInitiatedLogin($tenant));

        // When
        $login = $handler->handle($tenant, self::CLIENT_ID, null, $targetLinkUri) ?? static::fail('There is a login to begin.');

        // Then
        static::assertSame(self::INITIATE_LOGIN_URI . self::ISSUED_BY_THIS_PROVIDER, $login->location());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLandingPagesNobodyRegistered(): iterable
    {
        yield 'a page of somebody else' => ['https://attacker.example/landing'];
        yield 'the registered one with a path added' => [self::REDIRECT_URI . '/../elsewhere'];
        yield 'the registered one with a query added' => [self::REDIRECT_URI . '?next=https://attacker.example'];
        yield 'the registered one but for its case' => ['https://rp.example/CALLBACK'];
        yield 'a page registered by another client of the tenant' => ['https://spa.example/callback'];
        yield 'none at all' => [''];
        yield 'a value that is no URI' => ['not a uri'];
    }

    private static function handlerFor(
        Tenant $tenant,
        Client $client,
        ?SubjectIdentifierResolverInterface $subjects = null,
    ): ThirdPartyInitiatedLoginHandler {
        $clients = new InMemoryClientRepository();
        $clients->save($client);
        // the other client of the tenant, so that what one registered is never what another may be given
        $clients->save(Clients::public($tenant));

        return new ThirdPartyInitiatedLoginHandler($clients, $subjects ?? Subjects::ofAProvider());
    }
}
