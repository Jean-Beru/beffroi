<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Tenant\SelfServedClaims;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SelfServedClaimsTest extends TestCase
{
    /**
     * @param list<string> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsItAs(SelfServedClaims $claims, array $document): void
    {
        // When / Then
        static::assertSame($document, $claims->toDocument());
    }

    /**
     * @param list<string> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itComesBackOutOfItsDocument(SelfServedClaims $claims, array $document): void
    {
        // When / Then
        static::assertEquals($claims, SelfServedClaims::fromDocument($document));
    }

    /**
     * @return iterable<string, array{SelfServedClaims, list<string>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'two claims' => [new SelfServedClaims(['nickname', 'zoneinfo']), ['nickname', 'zoneinfo']];
        yield 'a tenant that lets a person change nothing' => [SelfServedClaims::none(), []];
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotClaimNames')]
    public function aDocumentThatIsNotClaimNamesIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        SelfServedClaims::fromDocument($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotClaimNames(): iterable
    {
        yield 'a name that is a number' => [[12], 'The claims a person may change of themselves are names.'];
        yield 'a name that is an object' => [
            [
                [
                    'name' => 'nickname',
                ],
            ],
            'The claims a person may change of themselves are names.',
        ];
        yield 'an empty name' => [[''], 'A claim a person may change of themselves has a name.'];
    }
}
