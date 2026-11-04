<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Token\ClientSubject;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClientSubjectTest extends TestCase
{
    /**
     * RFC 9068 §2.2
     */
    #[Test]
    public function itNamesTheClientItself(): void
    {
        // Given
        $client = Clients::service(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When
        $subject = ClientSubject::of($client);

        // Then
        static::assertSame('batch', $subject->value);
    }

    /**
     * OIDC Core §2, RFC 6749 appendix A.1
     */
    #[Test]
    #[DataProvider('provideIdentifiersNoSubjectCanBe')]
    public function itRefusesAnIdentifierNoSubjectCanBe(string $clientId): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('cannot be the "sub" of a token it holds for itself');

        // When
        ClientSubject::ofIdentifier($clientId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIdentifiersNoSubjectCanBe(): iterable
    {
        yield 'a space inside' => ['the batch'];
        yield 'empty' => [''];
    }
}
