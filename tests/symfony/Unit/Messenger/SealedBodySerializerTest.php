<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Messenger;

use Beffroi\Core\Tests\Domain\Event\EventsLeaveTheProcessTest;
use function array_keys;
use function array_map;
use function array_unique;
use function array_values;
use function base64_decode;
use function base64_encode;
use Beffroi\Bundle\Message\AdvanceKeyLifecycle;
use Beffroi\Bundle\Message\SendLogoutToken;
use Beffroi\Bundle\Messenger\SealedBodySerializer;
use Beffroi\Bundle\Messenger\TenantStamp;
use Beffroi\Bundle\Tests\Fixture\AmbientTenant;
use Beffroi\Bundle\Tests\Fixture\AskWhatIsKnown;
use Beffroi\Bundle\Tests\Fixture\EnrichTheProvenance;
use Beffroi\Bundle\Tests\Fixture\SomethingHappened;
use Beffroi\Bundle\Tests\Fixture\WriteBeforeAnswering;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodyOpener;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryMessageBodySealer;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Port\MessageBodyOpenerInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use DateTimeImmutable;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match_all;
use function serialize;
use function sprintf;
use function strlen;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Exception\MessageDecodingFailedException;
use Symfony\Component\Messenger\Stamp\ErrorDetailsStamp;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Symfony\Component\Messenger\Stamp\SentToFailureTransportStamp;
use Symfony\Component\Messenger\Stamp\StampInterface;
use Symfony\Component\Uid\Uuid;
use function unserialize;

/**
 * Decision 0020: what this provider writes to a transport leaves the process sealed. What the suites of
 * the two packages ask of every message, that it survive leaving the process, this asks of the shape it
 * leaves in: a body a broker cannot read, headers that name the class and the scope and nothing of a
 * person, and a message in the failure transport that an operator reads without its body being opened.
 */
final class SealedBodySerializerTest extends TestCase
{
    /**
     * The floor of what is searched for in an encoded envelope: a sealed body is bytes indistinguishable
     * from random, so a short string turns up in one by chance and the run goes red for nothing, as the
     * search of a dump has it (DumpGivesNothingAwayTest).
     */
    private const int SEARCHED_FROM = 8;

    /**
     * What the person of the message below is called and what names them to a client: the values of
     * provideWhatAMessageOfAPersonCarries(), here because the test and its provider must write the same
     * ones.
     */
    private const string USERNAME = 'alice@acme.example';

    private const string SUBJECT = 'alice-of-acme-0001';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private SealedBodySerializer $serializer;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->keys->save($this->messageKey($this->tenant));
        $this->serializer = $this->serializerOf($this->tenant, new SealedKeyProvider($this->keys, Keys::sealer()));
    }

    /**
     * Every message of the provider: one of each marker the contract routes (MessengerContract::routing())
     * and every event of the two packages, the suite of each being what holds its list to being whole.
     *
     * @return iterable<string, array{object}>
     */
    public static function messages(): iterable
    {
        yield 'a command' => [new AdvanceKeyLifecycle()];
        yield 'a command of its own' => [new EnrichTheProvenance(Uuid::v7())];
        yield 'an event of the bundle' => [new SomethingHappened('a page was rendered')];
        yield 'a notification' => [new SendLogoutToken(
            Fixtures::tenant(),
            'oidc-demo',
            'https://demo.localhost/backchannel-logout',
            'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature',
            Uuid::v7(),
            Fixtures::user()->subject,
            Fixtures::context(),
        )];
        yield 'a query' => [new AskWhatIsKnown('the sessions of alice')];
        yield 'a write the protocol waits for' => [new WriteBeforeAnswering('the consent')];
        foreach (EventsLeaveTheProcessTest::events() as $name => $case) {
            yield 'an event of the core: ' . $name => $case;
        }
        foreach (\Beffroi\Oidc\Tests\Domain\Event\EventsLeaveTheProcessTest::events() as $name => $case) {
            yield 'an event of the module: ' . $name => $case;
        }
    }

    #[Test]
    #[DataProvider('messages')]
    public function aMessageIsSealedOnItsWayOutAndIsTheSameMessageOnItsWayBack(object $message): void
    {
        // When
        $decoded = $this->serializer->decode($this->serializer->encode(new Envelope($message)));

        // Then
        static::assertSame(serialize($message), serialize($decoded->getMessage()));
    }

    /**
     * What DumpGivesNothingAwayTest asks of a dump, asked of what a broker keeps: the body is a compact
     * JWE, and none of the strings the message held is in it. A message that carries nothing long enough
     * to search for, a command that is a word and no data, is held to the first half only; what makes the
     * search mean something is the test below, which names what it looks for.
     */
    #[Test]
    #[DataProvider('messages')]
    public function theEncodedBodyCarriesNoneOfTheStringsTheMessageHeld(object $message): void
    {
        // Given
        $searched = self::stringsOf($message);

        // When
        $body = $this->serializer->encode(new Envelope($message))['body'];

        // Then
        static::assertCount(5, explode('.', $body));
        foreach ($searched as $string) {
            static::assertStringNotContainsString($string, $body, sprintf('the body of the message gives "%s" away.', $string));
        }
    }

    /**
     * What makes the search above mean something: the message the fixture writes carries what decision
     * 0011 seals in a column, and every one of those values is looked for by name. A green run is a search
     * that was looking.
     */
    #[Test]
    #[DataProvider('provideWhatAMessageOfAPersonCarries')]
    public function theEncodedBodyOfAMessageOfAPersonGivesNoneOfTheirValuesAway(string $value): void
    {
        // Given
        $message = new UserAuthenticated(self::sessionOfAPerson());

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertStringContainsString($value, serialize($message), 'a value the message does not carry is a value this test does not search for.');
        static::assertStringNotContainsString($value, $encoded['body']);
        foreach ($encoded['headers'] ?? [] as $header) {
            static::assertStringNotContainsString($value, $header);
        }
    }

    /**
     * The values the session of a person carries, which are columns decision 0011 seals: who signed in,
     * what names them to a client, and where the request came from. Each one is long enough that finding
     * it in a sealed body is a leak and never a coincidence (SEARCHED_FROM).
     *
     * @return iterable<string, array{string}>
     */
    public static function provideWhatAMessageOfAPersonCarries(): iterable
    {
        yield 'the username' => [self::USERNAME];
        yield 'the subject' => [self::SUBJECT];
        yield 'the address of the request' => ['203.0.113.10'];
        yield 'the user agent of the request' => ['Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0'];
    }

    /**
     * A session of someone whose every value is long enough to be searched for, which is what makes the
     * two tests above a search rather than a formality.
     */
    private static function sessionOfAPerson(): AuthenticationSession
    {
        return Fixtures::session(Fixtures::user(username: self::USERNAME, subject: self::SUBJECT));
    }

    /**
     * The other half: a header is in the clear, so nothing of a person is in one. What a transport carries
     * beside the body is the class of the message, which names a failure, and the scope it was written
     * under, which says which key to ask for.
     */
    #[Test]
    #[DataProvider('messages')]
    public function noHeaderCarriesAnythingOfTheMessageButItsClass(object $message): void
    {
        // Given
        $searched = self::stringsOf($message);

        // When
        $headers = $this->serializer->encode(new Envelope($message))['headers'] ?? [];

        // Then
        static::assertSame(
            [
                SealedBodySerializer::TYPE_HEADER,
                SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class,
            ],
            array_keys($headers),
        );
        static::assertSame($message::class, $headers[SealedBodySerializer::TYPE_HEADER]);
        static::assertSame([$this->tenant->slug], array_map(
            static fn (TenantStamp $stamp): string => $stamp->slug,
            self::stampsOf(TenantStamp::class, $headers[SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class]),
        ));
        foreach ($searched as $string) {
            if ($string === $message::class) {
                continue;
            }
            foreach ($headers as $name => $value) {
                static::assertStringNotContainsString($string, $value, sprintf('the header "%s" gives "%s" away.', $name, $string));
                static::assertStringNotContainsString($string, (string) base64_decode($value, true));
            }
        }
    }

    /**
     * The scope travels in a stamp so that a consumer knows which key to ask for before it touches the
     * body, and the stamp is never what decides: a body sealed elsewhere and carried in with its stamp
     * rewritten fails to open instead of opening here (the pattern of beffroi#436).
     */
    #[Test]
    public function aStampThatSaysTheWrongScopeMakesTheOpeningFail(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->keys->save($this->messageKey($other));
        $elsewhere = $this->serializerOf($other, new SealedKeyProvider($this->keys, Keys::sealer()))->encode(new Envelope(
            new SomethingHappened('something of another tenant'),
        ));
        $elsewhere['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class] = base64_encode(serialize([
            new TenantStamp($this->tenant->slug),
        ]));

        // When
        $decoded = $this->serializer->decode($elsewhere);

        // Then
        static::assertStringContainsString('sealed for another scope', self::failureOf($decoded)->getMessage());
    }

    /**
     * A message written for a tenant this process does not serve is not opened, and the refusal names
     * both: a worker reads which scope it was asked for.
     */
    #[Test]
    public function aMessageOfAnotherTenantIsNotOpenedHere(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class] = base64_encode(serialize([
            new TenantStamp('other'),
        ]));

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertSame(
            'The message was written for the tenant "other" and this process serves "acme".',
            self::failureOf($decoded)->getMessage(),
        );
    }

    /**
     * An envelope with no scope is not a message of this provider: it is refused rather than opened under
     * whatever the process happens to serve.
     */
    #[Test]
    public function anEnvelopeThatNamesNoScopeIsRefused(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        unset($encoded['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class]);

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertSame(
            'An encoded envelope of this provider names the tenant it was written for.',
            self::failureOf($decoded)->getMessage(),
        );
    }

    /**
     * The body decides what the message is, the header only says it: a type rewritten on a transport is a
     * refusal and never a message handed to a bus under a name it does not have.
     */
    #[Test]
    public function theBodyDecidesTheClassOfTheMessageAndNotTheHeader(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $encoded['headers'][SealedBodySerializer::TYPE_HEADER] = AdvanceKeyLifecycle::class;

        // When
        $decoded = $this->serializer->decode($encoded);

        // Then
        static::assertStringContainsString('opens as', self::failureOf($decoded)->getMessage());
    }

    /**
     * The third thing the decision asks of the failure transport: a message whose body nobody can open any
     * more is still named, dated and explained. The body goes on as it arrived, and what an operator reads
     * is read from the headers.
     */
    #[Test]
    public function aFailedMessageIsNamedDatedAndExplainedWithoutItsBodyBeingOpened(): void
    {
        // Given
        $message = new SomethingHappened('a page was rendered');
        $encoded = $this->serializer->encode(new Envelope($message));
        $refused = $this->serializerOf($this->tenant, new SealedKeyProvider(new InMemoryTenantKeyRepository(), Keys::sealer()));
        $failure = $refused->decode($encoded);
        $redeliveredAt = new DateTimeImmutable('2026-10-09T12:00:00+00:00');

        // When
        $written = $refused->encode($failure->with(
            new SentToFailureTransportStamp('async_priority_low'),
            new RedeliveryStamp(1, $redeliveredAt),
            ErrorDetailsStamp::create(new KmsUnavailableException('the vault did not answer')),
        ));

        // Then
        static::assertSame($encoded['body'], $written['body']);
        static::assertSame(SomethingHappened::class, $refused->getMessageType($written));
        static::assertSame(['2026-10-09T12:00:00+00:00'], array_map(
            static fn (RedeliveryStamp $stamp): string => $stamp->getRedeliveredAt()->format(DateTimeImmutable::RFC3339),
            self::stampsOf(RedeliveryStamp::class, $written['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . RedeliveryStamp::class] ?? ''),
        ));
        static::assertSame(['the vault did not answer'], array_map(
            static fn (ErrorDetailsStamp $stamp): string => $stamp->getExceptionMessage(),
            self::stampsOf(ErrorDetailsStamp::class, $written['headers'][SealedBodySerializer::STAMP_HEADER_PREFIX . ErrorDetailsStamp::class] ?? ''),
        ));
    }

    /**
     * A KMS that does not answer is a failure of the process and not of the message: it passes, so the
     * message is tried again rather than put in a transport nobody replays.
     */
    #[Test]
    public function aKmsThatDoesNotAnswerIsNotAMessageThrownAway(): void
    {
        // Given
        $encoded = $this->serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));
        $opener = self::createStub(MessageBodyOpenerInterface::class);
        $opener->method('open')->willThrowException(new KmsUnavailableException('the vault did not answer'));
        $worker = new SealedBodySerializer(
            new AmbientTenant($this->tenant),
            new JwtLibraryMessageBodySealer(new SealedKeyProvider($this->keys, Keys::sealer()), Algorithms::messageSealing()),
            $opener,
        );

        // Then
        $this->expectException(KmsUnavailableException::class);

        // When
        $worker->decode($encoded);
    }

    /**
     * What the decision buys on the path of a request: the half that seals is public, so a process that
     * writes messages asks the KMS nothing and a KMS that is down does not stop a login from being
     * recorded.
     */
    #[Test]
    public function sealingABodyAsksTheKmsNothing(): void
    {
        // Given
        $kms = self::createMock(KeySealerInterface::class);
        $kms->expects(static::never())->method('unseal');
        $serializer = $this->serializerOf($this->tenant, new SealedKeyProvider($this->keys, $kms));

        // When
        $encoded = $serializer->encode(new Envelope(new SomethingHappened('a page was rendered')));

        // Then
        static::assertCount(5, explode('.', $encoded['body']));
    }

    private function serializerOf(Tenant $tenant, SealedKeyProvider $keys): SealedBodySerializer
    {
        return new SealedBodySerializer(
            new AmbientTenant($tenant),
            new JwtLibraryMessageBodySealer($keys, Algorithms::messageSealing()),
            new JwtLibraryMessageBodyOpener($keys, Algorithms::messageSealing()),
        );
    }

    private function messageKey(Tenant $tenant): TenantKey
    {
        $pair = Keys::messagePair();
        $key = new TenantKey(
            $pair->kid,
            $tenant,
            Algorithms::messageSeal(),
            $pair->publicJwk,
            Keys::sealer()->seal($tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());

        return $key;
    }

    /**
     * What a decode that did not open came back with: the component wraps a refusal in an envelope rather
     * than throwing, so that a worker routes it to the failure transport like any other message.
     */
    private static function failureOf(Envelope $envelope): MessageDecodingFailedException
    {
        $failure = $envelope->getMessage();
        static::assertInstanceOf(MessageDecodingFailedException::class, $failure);

        return $failure;
    }

    /**
     * The strings a message holds, read from what the seal is given: every string of its serialization
     * long enough to be searched for, which is what makes this test grow with the messages rather than
     * with a list somebody keeps.
     *
     * @return list<string>
     */
    private static function stringsOf(object $message): array
    {
        preg_match_all('/s:(\d+):"((?:[^"\\\\]|\\\\.)*)";/', serialize($message), $matches, PREG_SET_ORDER);
        $searched = [];
        foreach ($matches as $match) {
            if (strlen($match[2]) >= self::SEARCHED_FROM) {
                $searched[] = $match[2];
            }
        }

        return array_values(array_unique($searched));
    }

    /**
     * The stamps a header carries, read back the way the serializer reads them.
     *
     * @template T of StampInterface
     *
     * @param class-string<T> $class
     *
     * @return non-empty-list<T>
     */
    private static function stampsOf(string $class, string $header): array
    {
        $decoded = base64_decode($header, true);
        static::assertIsString($decoded);
        $stamps = unserialize($decoded, [
            'allowed_classes' => true,
        ]);
        static::assertIsArray($stamps);
        static::assertNotSame([], $stamps);
        $read = [];
        foreach ($stamps as $stamp) {
            static::assertInstanceOf($class, $stamp);
            $read[] = $stamp;
        }

        return $read;
    }
}
