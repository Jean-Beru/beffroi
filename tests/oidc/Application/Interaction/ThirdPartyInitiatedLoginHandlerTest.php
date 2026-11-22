<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Interaction;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Beffroi\Oidc\Application\Interaction\ThirdPartyInitiatedLoginHandler;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §4
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
     * OIDC Core §4
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
     * OIDC Core §8
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
     * OIDC Core §8
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
     * RFC 6749 §3.1.2.3
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
     * OIDC Core §4
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
        // Another client of the tenant, so that what one registered is never what another is given.
        $clients->save(Clients::public($tenant));

        return new ThirdPartyInitiatedLoginHandler($clients, $subjects ?? Subjects::ofAProvider());
    }
}
