<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Messenger;

use App\Messenger\LaneDsn;
use App\Messenger\MessengerContract;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\RuntimeException;

final class LaneDsnTest extends TestCase
{
    private const string VARIABLE = 'BEFFROI_LANES_OF_THIS_TEST';

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
