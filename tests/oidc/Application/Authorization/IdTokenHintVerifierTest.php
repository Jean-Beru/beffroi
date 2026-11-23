<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Authorization;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Application\Token\JwtAccessTokenIssuer;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\EndSession\LogoutToken;
use Beffroi\Oidc\Domain\Introspection\IntrospectionResponse;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeJwsVerifier;
use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Throwable;

final class IdTokenHintVerifierTest extends TestCase
{
    private const string SID = '01996f5a-1c2e-7b3c-9d4e-5f6a7b8c9d0e';

    private const string TOKEN = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.eyJpc3MiOiJodHRwczovL2lkLmFjbWUuZXhhbXBsZSJ9.c2lnbmF0dXJl';

    private Tenant $tenant;

    private Client $client;

    private FakeJwsVerifier $jws;

    private IdTokenHintVerifier $verifier;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::public($this->tenant);
        $this->jws = new FakeJwsVerifier();
        $this->verifier = new IdTokenHintVerifier($this->jws);
    }

    /**
     * OIDC Core §3.1.2.1, §2
     */
    #[Test]
    #[DataProvider('provideValidHints')]
    public function itReadsTheSubjectOfAnIdTokenIssuedHereToThisClient(string $payload): void
    {
        // Given
        $this->jws->knows($this->tenant, self::TOKEN, $payload);

        // When
        $subject = $this->verifier->verify($this->client, self::TOKEN);

        // Then
        static::assertSame('alice-subject', (string) $subject);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidHints(): iterable
    {
        yield 'single audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","exp":1}'];
        yield 'audience list' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["other","spa"],"exp":1}'];
        yield 'profile claims' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","address":{"country":"FR"}}'];
    }

    /**
     * @param class-string<Throwable>|null $cause
     */
    #[Test]
    #[DataProvider('provideForeignHints')]
    public function itRefusesATokenNotIssuedHere(?string $payload, ?string $cause = null): void
    {
        // Given
        if ($payload !== null) {
            $this->jws->knows($this->tenant, self::TOKEN, $payload);
        }

        // When
        try {
            $this->verifier->verify($this->client, self::TOKEN);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertTrue($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued by this provider.', $exception->errorDescription);
            if ($cause === null) {
                static::assertNull($exception->getPrevious());
            } else {
                static::assertInstanceOf($cause, $exception->getPrevious());
            }
        }
    }

    /**
     * @return iterable<string, array{?string, 1?: class-string<Throwable>}>
     */
    public static function provideForeignHints(): iterable
    {
        yield 'signature' => [null, InvalidJwsException::class];
        yield 'not JSON' => ['not json', JsonException::class];
        yield 'a list' => ['["https://id.acme.example"]'];
        yield 'a string' => ['"https://id.acme.example"'];
        yield 'null' => ['null'];
        yield 'too deep' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","a":{"b":{"c":{"d":1}}}}', JsonException::class];
        yield 'no issuer' => ['{"sub":"alice-subject","aud":"spa"}'];
        yield 'other issuer' => ['{"iss":"https://id.other.example","sub":"alice-subject","aud":"spa"}'];
        yield 'issuer not a string' => ['{"iss":["https://id.acme.example"],"sub":"alice-subject","aud":"spa"}'];
        yield 'no subject' => ['{"iss":"https://id.acme.example","aud":"spa"}'];
        yield 'subject not a string' => ['{"iss":"https://id.acme.example","sub":42,"aud":"spa"}'];
        yield 'subject empty' => ['{"iss":"https://id.acme.example","sub":"","aud":"spa"}'];
    }

    #[Test]
    #[DataProvider('provideOtherClientHints')]
    public function itRefusesATokenIssuedToAnotherClient(string $payload): void
    {
        // Given
        $this->jws->knows($this->tenant, self::TOKEN, $payload);

        // When
        try {
            $this->verifier->verify($this->client, self::TOKEN);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertTrue($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued to this client.', $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherClientHints(): iterable
    {
        yield 'no audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject"}'];
        yield 'other audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"other"}'];
        yield 'other audiences' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["other","another"]}'];
        yield 'audience map' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":{"a":"spa"}}'];
        yield 'audience under the key 0 of an object' => [
            '{"iss":"https://id.acme.example","sub":"alice-subject","aud":{"0":"spa"},"exp":1,"iat":1,"auth_time":1}',
        ];
        yield 'audience not a string' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":42}'];
    }

    /**
     * RFC 8725 §3.11, RFC 9068 §5, OIDC Core §3.1.2.1
     */
    #[Test]
    #[DataProvider('provideTypes')]
    public function itRefusesATokenThatNamesAType(string $type): void
    {
        // Given
        $this->jws->knows($this->tenant, self::TOKEN, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa"}', [
            'typ' => $type,
        ]);

        // When
        try {
            $this->verifier->verify($this->client, self::TOKEN);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertTrue($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued by this provider.', $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTypes(): iterable
    {
        yield 'an access token' => [JwtAccessTokenIssuer::TYPE];
        yield 'a logout token' => [LogoutToken::TYPE];
        yield 'an introspection response' => [IntrospectionResponse::JWT_TYPE];
        yield 'a JWT' => ['JWT'];
        yield 'an empty type' => [''];
    }

    #[Test]
    public function itVerifiesAgainstTheKeysOfTheTenantOfTheClient(): void
    {
        // Given
        $this->jws->knows(
            Fixtures::tenant('other', 'https://id.other.example'),
            self::TOKEN,
            '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa"}',
        );

        // Then
        $this->expectException(InvalidRequestException::class);

        // When
        $this->verifier->verify($this->client, self::TOKEN);
    }

    /**
     * RP-Initiated Logout §2, architecture §4.6
     *
     * @param list<string> $audiences
     */
    #[Test]
    #[DataProvider('provideReadableHints')]
    public function itReadsSubjectAudiencesAndSessionOfAnIdTokenIssuedHere(string $payload, array $audiences, ?string $sid): void
    {
        // Given
        $this->jws->knows($this->tenant, self::TOKEN, $payload);

        // When
        $hint = $this->verifier->read($this->tenant, self::TOKEN, false);

        // Then
        static::assertSame('alice-subject', (string) $hint->subject);
        static::assertSame($audiences, $hint->audiences);
        static::assertSame($sid, $hint->sessionId?->toRfc4122());
        static::assertSame($audiences !== [], $hint->isFor('spa'));
        static::assertFalse($hint->isFor('other'));
    }

    /**
     * @return iterable<string, array{string, list<string>, ?string}>
     */
    public static function provideReadableHints(): iterable
    {
        yield 'as issued here' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","exp":1,"sid":"' . self::SID . '"}', ['spa'], self::SID];
        yield 'audience list' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["spa","another"]}', ['spa', 'another'], null];
        yield 'no audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject"}', [], null];
        yield 'audience map' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":{"a":"spa"}}', [], null];
        yield 'audience not a string' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":42}', [], null];
        yield 'audience list with a number' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["spa",42]}', [], null];
    }

    #[Test]
    #[DataProvider('provideSessionIdsNotIssuedHere')]
    public function itRefusesASessionIdentifierItDidNotWrite(string $sid): void
    {
        // Given
        $this->jws->knows($this->tenant, self::TOKEN, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","sid":' . $sid . '}');

        // When
        try {
            $this->verifier->read($this->tenant, self::TOKEN, false);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertFalse($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued by this provider.', $exception->errorDescription);
        }
    }

    /**
     * RP-Initiated Logout §2, §6, RFC 8725 §3.11
     */
    #[Test]
    #[DataProvider('provideTypes')]
    public function itReadsNoSessionFromATokenThatNamesAType(string $type): void
    {
        // Given
        $this->jws->knows($this->tenant, self::TOKEN, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","sid":"' . self::SID . '"}', [
            'typ' => $type,
        ]);

        // When
        try {
            $this->verifier->read($this->tenant, self::TOKEN, false);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertFalse($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued by this provider.', $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSessionIdsNotIssuedHere(): iterable
    {
        yield 'a number' => ['42'];
        yield 'empty' => ['""'];
        yield 'not a UUID' => ['"session-1"'];
        yield 'base58' => ['"' . Uuid::fromString(self::SID)->toBase58() . '"'];
    }

    /**
     * @param class-string<Throwable>|null $cause
     */
    #[Test]
    #[DataProvider('provideForeignHints')]
    public function itRefusesATokenNotIssuedHereWithoutRedirecting(?string $payload, ?string $cause = null): void
    {
        // Given
        if ($payload !== null) {
            $this->jws->knows($this->tenant, self::TOKEN, $payload);
        }

        // When
        try {
            $this->verifier->read($this->tenant, self::TOKEN, false);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            // Then
            static::assertFalse($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued by this provider.', $exception->errorDescription);
            static::assertSame($cause, $exception->getPrevious() === null ? null : $exception->getPrevious()::class);
        }
    }
}
