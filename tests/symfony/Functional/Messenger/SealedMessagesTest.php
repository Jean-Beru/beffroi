<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Messenger;

use Beffroi\Bundle\Message\AdvanceKeyLifecycle;
use Beffroi\Bundle\Messenger\MessengerContract;
use Beffroi\Bundle\Messenger\SealedBodySerializer;
use Beffroi\Bundle\Messenger\TenantStamp;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Application\Key\TenantKeyRotator;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Port\MessageSealingAlgorithmsInterface;
use Beffroi\Core\Port\PublicKeySetProviderInterface;
use function base64_encode;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function serialize;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;

/**
 * Decision 0020, wired: what every transport of this provider encodes with is the serializer of the bundle,
 * and what it writes is sealed to the key the tenant keeps for it. The unit test of the serializer says
 * what it does with a message; this says that this is what a deployment gets, with the tenant of the
 * kernel, its KMS and its key store.
 *
 * The transports of the test kernel are synchronous, where nothing is ever encoded, which is why what is
 * asked here is asked of the serializer the component hands a transport and not of a message dispatched on
 * a bus.
 */
final class SealedMessagesTest extends DatabaseTestCase
{
    private string $directory;

    private SerializerInterface $serializer;

    protected function setUp(): void
    {
        parent::setUp();
        $cacheDir = self::getContainer()->getParameter('kernel.cache_dir');
        static::assertIsString($cacheDir);
        $this->directory = $cacheDir . '/keys';
        new Filesystem()->remove($this->directory);
        $this->serializer = self::service('test.beffroi.messenger_serializer', SerializerInterface::class);
        self::service('test.beffroi.key_rotator', TenantKeyRotator::class)
            ->rotate(
                self::tenant(),
                self::service('test.beffroi.message_sealing_algorithms', MessageSealingAlgorithmsInterface::class)->defaultAlgorithm(),
                self::context(),
            );
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        new Filesystem()->remove($this->directory);
    }

    /**
     * The contract names the serializer of the bundle, so what the component hands every transport is that
     * one: a deployment that declares a transport of its own gets it without asking.
     */
    #[Test]
    public function everyTransportEncodesWithTheSerializerOfTheBundle(): void
    {
        // When / Then
        static::assertInstanceOf(SealedBodySerializer::class, $this->serializer);
    }

    /**
     * The round trip through the wiring: the tenant of the kernel, its KMS and the key the rotation of the
     * setup generated.
     */
    #[Test]
    public function aMessageIsSealedToTheKeyOfTheTenantAndOpensBack(): void
    {
        // Given
        $message = new KmsUnavailable(self::now(), self::tenant(), self::context(), 'the vault did not answer');

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertCount(5, explode('.', $encoded['body']));
        static::assertSame(serialize($message), serialize($this->serializer->decode($encoded)->getMessage()));
    }

    /**
     * What the criterion of the issue asks of the body: none of the values the message carried, and the
     * same values are what the search of a dump looks for in a column (DumpGivesNothingAwayTest).
     */
    #[Test]
    #[DataProvider('provideWhatTheMessageCarries')]
    public function theEncodedBodyGivesNoneOfTheValuesTheMessageCarriedAway(string $value): void
    {
        // Given
        $message = new KmsUnavailable(self::now(), self::tenant(), self::context(), 'the vault did not answer');

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertStringContainsString($value, serialize($message));
        static::assertStringNotContainsString($value, $encoded['body']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatTheMessageCarries(): iterable
    {
        yield 'the address of the request' => [SealedRows::IP_ADDRESS];
        yield 'the user agent of the request' => [SealedRows::USER_AGENT];
        yield 'what the provider had to say' => ['the vault did not answer'];
    }

    /**
     * What travels in the clear, named: the class of the message and the scope it was written under. The
     * "kid" of the key is in the protected header of the body, which carries it anyway, and nothing else
     * is anywhere.
     */
    #[Test]
    public function theHeadersNameTheClassAndTheScopeAndNothingElse(): void
    {
        // When
        $encoded = $this->serializer->encode(new Envelope(new AdvanceKeyLifecycle()));

        // Then
        static::assertSame(
            [
                SealedBodySerializer::TYPE_HEADER => AdvanceKeyLifecycle::class,
                SealedBodySerializer::STAMP_HEADER_PREFIX . TenantStamp::class => base64_encode(serialize([
                    new TenantStamp(self::tenant()->slug),
                ])),
            ],
            $encoded['headers'] ?? [],
        );
    }

    /**
     * The key a body is sealed to is not in the JWK Set: a key published there would let any reader of the
     * discovery document seal a body this provider opens.
     */
    #[Test]
    public function theKeyAMessageIsSealedToIsNotPublished(): void
    {
        // Given
        $sealing = self::service('test.beffroi.message_sealing_algorithms', MessageSealingAlgorithmsInterface::class)->defaultAlgorithm()->name();

        // When
        $published = self::service('test.beffroi.public_keys', PublicKeySetProviderInterface::class)->publicKeys(self::tenant());

        // Then
        foreach ($published->keys as $key) {
            static::assertNotSame($sealing, $key->algorithm->name());
        }
    }

    /**
     * The failure transport is a transport like the others, so what waits in it is sealed too: it is the
     * one that keeps what it is given the longest.
     */
    #[Test]
    public function theFailureTransportIsNotAnExceptionToTheSealing(): void
    {
        // Given
        $configuration = MessengerContract::configuration();
        $serializer = $configuration['serializer'];
        $transports = $configuration['transports'];

        // When / Then
        static::assertIsArray($serializer);
        static::assertSame(MessengerContract::SERIALIZER, $serializer['default_serializer'] ?? null);
        static::assertIsArray($transports);
        static::assertArrayNotHasKey('serializer', (array) ($transports[MessengerContract::FAILURE_TRANSPORT] ?? []));
    }
}
