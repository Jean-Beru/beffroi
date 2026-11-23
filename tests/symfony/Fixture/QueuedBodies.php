<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Doctrine\DBAL\Connection;
use Doctrine\Persistence\ConnectionRegistry;
use stdClass;
use Symfony\Component\Messenger\Bridge\Doctrine\Transport\DoctrineTransportFactory;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Transport\Serialization\SerializerInterface;
use Symfony\Component\Messenger\Transport\SetupableTransportInterface;

/**
 * A sealed body written to a Doctrine transport of a database a test holds, as Messenger writes it.
 */
final readonly class QueuedBodies
{
    public static function send(Connection $connection, string $dsn, string $sealedBody): void
    {
        $transport = new DoctrineTransportFactory(self::registryOf($connection))->createTransport($dsn, [], self::serializerOf($sealedBody));
        if ($transport instanceof SetupableTransportInterface) {
            $transport->setup();
        }
        $transport->send(new Envelope(new stdClass()));
    }

    private static function registryOf(Connection $connection): ConnectionRegistry
    {
        return new readonly class($connection) implements ConnectionRegistry {
            public function __construct(
                private Connection $connection,
            ) {
            }

            public function getDefaultConnectionName(): string
            {
                return 'default';
            }

            public function getConnection(?string $name = null): object
            {
                return $this->connection;
            }

            public function getConnections(): array
            {
                return ['default' => $this->connection];
            }

            public function getConnectionNames(): array
            {
                return ['default' => 'default'];
            }
        };
    }

    private static function serializerOf(string $sealedBody): SerializerInterface
    {
        return new readonly class($sealedBody) implements SerializerInterface {
            public function __construct(
                private string $sealedBody,
            ) {
            }

            public function decode(array $encodedEnvelope): Envelope
            {
                return new Envelope(new stdClass());
            }

            public function encode(Envelope $envelope): array
            {
                return [
                    'body' => $this->sealedBody,
                    'headers' => [],
                ];
            }
        };
    }
}
