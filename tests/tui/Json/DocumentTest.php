<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Json;

use Beffroi\Tui\Json\Document;
use Beffroi\Tui\Json\UnreadableDocumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A member is read as what it is, and refused when it is not.
 */
final class DocumentTest extends TestCase
{
    #[Test]
    public function anEmptyJsonObjectIsADocument(): void
    {
        // When
        $document = Document::decode('{}', 'answer');

        // Then
        static::assertSame([], $document->members);
    }

    #[Test]
    #[DataProvider('provideWhatIsNoJsonObject')]
    public function whatIsNoJsonObjectIsRefused(string $json): void
    {
        // Then
        $this->expectException(UnreadableDocumentException::class);

        // When
        Document::decode($json, 'answer');
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoJsonObject(): iterable
    {
        yield 'not JSON' => ['<html>'];
        yield 'a list' => ['["issuer"]'];
        yield 'a string' => ['"issuer"'];
        yield 'a number' => ['42'];
    }

    /**
     * Decision 0006: no boolean coming from a third party is ever cast.
     */
    #[Test]
    #[DataProvider('provideWhatIsNoBoolean')]
    public function aBooleanIsAJsonBooleanAndNothingReadAsOne(mixed $value): void
    {
        // Given
        $document = new Document([
            'authorization_response_iss_parameter_supported' => $value,
        ]);

        // Then
        $this->expectException(UnreadableDocumentException::class);

        // When
        $document->isTrue('authorization_response_iss_parameter_supported');
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideWhatIsNoBoolean(): iterable
    {
        yield 'the string "true"' => ['true'];
        yield 'one' => [1];
        yield 'a list' => [[true]];
    }

    #[Test]
    public function anAbsentBooleanIsNo(): void
    {
        // When / Then
        static::assertFalse(new Document()->isTrue('require_pushed_authorization_requests'));
    }

    #[Test]
    public function aListOfStringsHoldsStringsOnly(): void
    {
        // Given
        $document = new Document([
            'acr_values_supported' => ['phr', 2],
        ]);

        // Then
        $this->expectException(UnreadableDocumentException::class);
        $this->expectExceptionMessageIs('The member "acr_values_supported" must be a JSON list of strings.');

        // When
        $document->strings('acr_values_supported');
    }

    #[Test]
    public function aRequiredStringIsNotEmpty(): void
    {
        // Given
        $document = new Document([
            'client_id' => '',
        ]);

        // Then
        $this->expectException(UnreadableDocumentException::class);
        $this->expectExceptionMessageIs('The member "client_id" must be a string that is not empty.');

        // When
        $document->string('client_id');
    }

    /**
     * What a document does not say is not a no.
     *
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideNullableBooleans')]
    public function aBooleanThatMayBeUnsaidIsNullWhenUnsaid(array $members, ?bool $read): void
    {
        // When / Then
        static::assertSame($read, new Document($members)->nullableBool('past_its_age'));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, ?bool}>
     */
    public static function provideNullableBooleans(): iterable
    {
        yield 'absent' => [[], null];
        yield 'null' => [['past_its_age' => null], null];
        yield 'true' => [['past_its_age' => true], true];
        yield 'false' => [['past_its_age' => false], false];
    }

    #[Test]
    public function aListOfObjectsIsReadAsDocumentsInTheirOrder(): void
    {
        // Given
        $document = new Document([
            'clients' => [['client_id' => 'one'], ['client_id' => 'two']],
        ]);

        // When
        $clients = $document->documents('clients');

        // Then
        static::assertSame(['one', 'two'], [$clients[0]->string('client_id'), $clients[1]->string('client_id')]);
    }

    #[Test]
    public function anAbsentListOfObjectsIsNone(): void
    {
        // When / Then
        static::assertSame([], new Document()->documents('clients'));
    }

    /**
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideWhatIsNoListOfObjects')]
    public function aListOfObjectsHoldsObjectsOnly(array $members, string $message): void
    {
        // Then
        $this->expectException(UnreadableDocumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new Document($members)->documents('clients');
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideWhatIsNoListOfObjects(): iterable
    {
        yield 'an object' => [['clients' => ['client_id' => 'one']], 'The member "clients" must be a JSON list.'];
        yield 'a string' => [['clients' => 'one'], 'The member "clients" must be a JSON list.'];
        yield 'a list of strings' => [['clients' => ['one']], 'The entry 0 of the member "clients" must be a JSON object, got string.'];
    }
}
