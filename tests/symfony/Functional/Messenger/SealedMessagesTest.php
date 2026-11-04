<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Messenger;

use App\Message\AdvanceKeyLifecycle;
use App\Message\CheckThePasswordAgainstTheBreaches;
use App\Messenger\MessengerContract;
use App\Messenger\SealedBodySerializer;
use App\Messenger\TenantStamp;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Application\Key\KeyStaging;
use Beffroi\Core\Application\Key\KeyTakeOver;
use Beffroi\Core\Domain\Credential\PasswordDigest;
use Beffroi\Core\Domain\Event\KmsUnavailable;
use Beffroi\Core\Domain\Event\TenantKeyStaged;
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
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0020
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
        self::service('test.beffroi.key_take_over', KeyTakeOver::class)
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

    #[Test]
    public function everyTransportEncodesWithTheSerializerOfTheProvider(): void
    {
        // When / Then
        static::assertInstanceOf(SealedBodySerializer::class, $this->serializer);
    }

    #[Test]
    public function theFirstMessageKeyOfATenantSealsTheEventThatAnnouncesIt(): void
    {
        // Given
        new Filesystem()->remove($this->directory);
        $staged = self::service('test.beffroi.key_staging', KeyStaging::class)
            ->stage(
                self::tenant(),
                self::service('test.beffroi.message_sealing_algorithms', MessageSealingAlgorithmsInterface::class)->defaultAlgorithm(),
                self::context(),
            );

        // When
        $encoded = $this->serializer->encode(new Envelope(new TenantKeyStaged($staged, self::now(), self::context())));

        // Then
        static::assertTrue($staged->isStaged());
        static::assertCount(5, explode('.', $encoded['body']));
        static::assertSame(TenantKeyStaged::class, $encoded['headers'][SealedBodySerializer::TYPE_HEADER] ?? null);
    }

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

    #[Test]
    public function theDigestOfAPasswordLeavesSealed(): void
    {
        // Given
        $digest = PasswordDigest::of('correct horse battery staple');
        $message = new CheckThePasswordAgainstTheBreaches(Uuid::v7(), $digest->value);

        // When
        $encoded = $this->serializer->encode(new Envelope($message));

        // Then
        static::assertStringContainsString($digest->value, serialize($message));
        static::assertStringNotContainsString($digest->value, $encoded['body']);
    }

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
