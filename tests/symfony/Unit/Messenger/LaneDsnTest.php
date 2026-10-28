<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Messenger;

use Beffroi\Bundle\Messenger\LaneDsn;
use Beffroi\Bundle\Messenger\MessengerContract;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

/**
 * Issue #919: one DSN moves the four lanes and keeps them four. `{lane}` is where the name of each lane goes,
 * and a DSN that names none is refused rather than served as one queue. Read through a container, as the
 * transport of a lane reads it, under a variable of this test so that the environment it runs in is not
 * what it reads.
 */
final class LaneDsnTest extends TestCase
{
    private const string VARIABLE = 'BEFFROI_LANES_OF_THIS_TEST';

    /**
     * An image deployed with nothing named needs no broker, and its lanes are four queues of the database:
     * in one queue, the receiver of the first lane named would take every message.
     */
    #[Test]
    #[DataProvider('provideLanes')]
    public function eachLaneIsAQueueOfItsOwnInTheDatabaseByDefault(string $lane): void
    {
        // When
        $dsn = self::resolved($lane, MessengerContract::DEFAULT_DSN);

        // Then
        static::assertSame('doctrine://default?queue_name=' . $lane, $dsn);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLanes(): iterable
    {
        foreach (MessengerContract::LANES as $lane) {
            yield $lane => [$lane];
        }
    }

    /**
     * A broker takes the lane where the DSN puts it, here the name of a Redis stream, and nothing reads the
     * scheme to know so.
     */
    #[Test]
    public function theLaneGoesWhereTheDsnOfADeploymentPutsIt(): void
    {
        // When
        $dsn = self::resolved('async_notifications', 'redis://beffroi:secret@redis:6379/beffroi_{lane}');

        // Then
        static::assertSame('redis://beffroi:secret@redis:6379/beffroi_async_notifications', $dsn);
    }

    #[Test]
    public function aDsnThatNamesNoLaneIsRefused(): void
    {
        // Then
        $this->expectException(RuntimeException::class);

        // When
        self::resolved('async_priority_high', 'redis://beffroi:secret@redis:6379/messages');
    }

    /**
     * The DSN of a broker carries its credentials, and a refusal ends in a log.
     */
    #[Test]
    public function theRefusalNamesTheVariableAndNotItsValue(): void
    {
        // Given
        $refusal = '';

        // When
        try {
            self::resolved('async_priority_high', 'redis://beffroi:secret@redis:6379/messages');
        } catch (RuntimeException $exception) {
            $refusal = $exception->getMessage();
        }

        // Then
        static::assertStringContainsString(self::VARIABLE, $refusal);
        static::assertStringNotContainsString('secret', $refusal);
    }

    /**
     * What another processor made of the variable first, a JSON document for one, is no DSN.
     */
    #[Test]
    public function aValueThatIsNoStringIsRefused(): void
    {
        // Then
        $this->expectException(RuntimeException::class);

        // When
        new LaneDsn()->getEnv(LaneDsn::PREFIX, 'async_priority_low:json:' . self::VARIABLE, static fn (): array => ['dsn' => '{lane}']);
    }

    #[Test]
    public function aNameThatCarriesNoLaneIsRefused(): void
    {
        // Then
        $this->expectException(RuntimeException::class);

        // When
        new LaneDsn()->getEnv(LaneDsn::PREFIX, self::VARIABLE, static fn (): string => MessengerContract::DEFAULT_DSN);
    }

    private static function resolved(string $lane, string $dsn): mixed
    {
        $container = new ContainerBuilder();
        $container->register(LaneDsn::class, LaneDsn::class)->addTag('container.env_var_processor');
        $container->setParameter('env(' . self::VARIABLE . ')', $dsn);
        $container->setParameter('lane', LaneDsn::of($lane, self::VARIABLE));
        $container->compile(true);

        return $container->getParameter('lane');
    }
}
