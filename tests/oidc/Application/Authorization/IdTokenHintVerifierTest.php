<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Authorization;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeJwsVerifier;
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
     * OIDC Core §3.1.2.1: the hint names the end user by "sub"; §2: "aud" is a string or a list, "exp"
     * is not looked at because the hint may describe a past session.
     */
    #[Test]
    #[DataProvider('validHints')]
    public function itReadsTheSubjectOfAnIdTokenIssuedHereToThisClient(string $payload): void
    {
        $this->jws->knows($this->tenant, self::TOKEN, $payload);

        static::assertSame('alice-subject', (string) $this->verifier->verify($this->client, self::TOKEN));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validHints(): iterable
    {
        yield 'single audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","exp":1}'];
        yield 'audience list' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["other","spa"],"exp":1}'];
        yield 'profile claims' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","address":{"country":"FR"}}'];
    }

    /**
     * A token that does not verify against the keys of the tenant, or is not a JSON object with the
     * "iss" of the tenant and a "sub", was not issued here: invalid_request, sent back to the client,
     * with the cause kept for the logs.
     *
     * @param class-string<Throwable>|null $cause
     */
    #[Test]
    #[DataProvider('foreignHints')]
    public function itRefusesATokenNotIssuedHere(?string $payload, ?string $cause = null): void
    {
        if ($payload !== null) {
            $this->jws->knows($this->tenant, self::TOKEN, $payload);
        }

        try {
            $this->verifier->verify($this->client, self::TOKEN);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
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
    public static function foreignHints(): iterable
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

    /**
     * A token of this provider but for another client is refused too: a client learns nothing from a
     * token it did not obtain.
     */
    #[Test]
    #[DataProvider('otherClientHints')]
    public function itRefusesATokenIssuedToAnotherClient(string $payload): void
    {
        $this->jws->knows($this->tenant, self::TOKEN, $payload);

        try {
            $this->verifier->verify($this->client, self::TOKEN);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            static::assertTrue($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued to this client.', $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherClientHints(): iterable
    {
        yield 'no audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject"}'];
        yield 'other audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"other"}'];
        yield 'other audiences' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["other","another"]}'];
        yield 'audience map' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":{"a":"spa"}}'];
        yield 'audience not a string' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":42}'];
    }

    /**
     * The keys are those of the client's tenant: a token of another tenant of the same deployment does
     * not verify.
     */
    #[Test]
    public function itVerifiesAgainstTheKeysOfTheTenantOfTheClient(): void
    {
        $this->jws->knows(Fixtures::tenant('other', 'https://id.other.example'), self::TOKEN, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa"}');

        $this->expectException(InvalidRequestException::class);
        $this->verifier->verify($this->client, self::TOKEN);
    }

    /**
     * RP-Initiated Logout §2: the logout endpoint reads the hint before it knows the client, and finds
     * the client in "aud" and the session in "sid" (architecture §4.6). "exp" is not looked at: §2
     * says the provider should accept an expired token.
     *
     * @param list<string> $audiences
     */
    #[Test]
    #[DataProvider('readableHints')]
    public function itReadsSubjectAudiencesAndSessionOfAnIdTokenIssuedHere(string $payload, array $audiences, ?string $sid): void
    {
        $this->jws->knows($this->tenant, self::TOKEN, $payload);

        $hint = $this->verifier->read($this->tenant, self::TOKEN, false);

        static::assertSame('alice-subject', (string) $hint->subject);
        static::assertSame($audiences, $hint->audiences);
        static::assertSame($sid, $hint->sessionId?->toRfc4122());
        static::assertSame($audiences !== [], $hint->isFor('spa'));
        static::assertFalse($hint->isFor('other'));
    }

    /**
     * @return iterable<string, array{string, list<string>, ?string}>
     */
    public static function readableHints(): iterable
    {
        yield 'as issued here' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","exp":1,"sid":"' . self::SID . '"}', ['spa'], self::SID];
        yield 'audience list' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["spa","another"]}', ['spa', 'another'], null];
        yield 'no audience' => ['{"iss":"https://id.acme.example","sub":"alice-subject"}', [], null];
        yield 'audience map' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":{"a":"spa"}}', [], null];
        yield 'audience not a string' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":42}', [], null];
        yield 'audience list with a number' => ['{"iss":"https://id.acme.example","sub":"alice-subject","aud":["spa",42]}', [], null];
    }

    /**
     * The "sid" this provider writes is a UUID: any other shape was not issued here. The flag says
     * whether the error may be sent to a client; the logout endpoint never redirects one (§4).
     */
    #[Test]
    #[DataProvider('sessionIdsNotIssuedHere')]
    public function itRefusesASessionIdentifierItDidNotWrite(string $sid): void
    {
        $this->jws->knows($this->tenant, self::TOKEN, '{"iss":"https://id.acme.example","sub":"alice-subject","aud":"spa","sid":' . $sid . '}');

        try {
            $this->verifier->read($this->tenant, self::TOKEN, false);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            static::assertFalse($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued by this provider.', $exception->errorDescription);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function sessionIdsNotIssuedHere(): iterable
    {
        yield 'a number' => ['42'];
        yield 'empty' => ['""'];
        yield 'not a UUID' => ['"session-1"'];
        yield 'base58' => ['"' . Uuid::fromString(self::SID)->toBase58() . '"'];
    }

    /**
     * Every refusal of read() carries the flag it was given, so that the authorization endpoint sends
     * the error back and the logout endpoint shows it.
     *
     * @param class-string<Throwable>|null $cause
     */
    #[Test]
    #[DataProvider('foreignHints')]
    public function itRefusesATokenNotIssuedHereWithoutRedirecting(?string $payload, ?string $cause = null): void
    {
        if ($payload !== null) {
            $this->jws->knows($this->tenant, self::TOKEN, $payload);
        }

        try {
            $this->verifier->read($this->tenant, self::TOKEN, false);
            static::fail('The hint should have been refused.');
        } catch (InvalidRequestException $exception) {
            static::assertFalse($exception->redirectable);
            static::assertSame('The id_token_hint parameter is not an ID token issued by this provider.', $exception->errorDescription);
            static::assertSame($cause, $exception->getPrevious() === null ? null : $exception->getPrevious()::class);
        }
    }
}
