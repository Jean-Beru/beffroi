<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\Webauthn\Rs1RefusingAttestationStatementSupport;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingAttestationStatementSupport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\TrustPath\EmptyTrustPath;

final class Rs1RefusingAttestationStatementSupportTest extends TestCase
{
    /**
     * Decision 0033, RFC 8812 §2: a statement signed with RS1 (COSE -65535) is refused before the format reads
     * it, so the library never asks web-auth/cose-lib for SHA-1.
     */
    #[Test]
    #[DataProvider('provideTheIdentifierOfRs1')]
    public function aStatementSignedWithRs1IsRefusedBeforeTheFormatVerifiesIt(int|string $algorithm): void
    {
        // Given
        $format = new RecordingAttestationStatementSupport();
        $support = new Rs1RefusingAttestationStatementSupport($format);
        $statement = AttestationStatement::createSelf('packed', ['alg' => $algorithm, 'sig' => 'signature'], EmptyTrustPath::create());

        // When
        $valid = $support->isValid('hash', $statement, Fixtures::authenticatorData());

        // Then
        static::assertFalse($valid);
        static::assertSame(0, $format->verified);
    }

    /**
     * @return iterable<string, array{int|string}>
     */
    public static function provideTheIdentifierOfRs1(): iterable
    {
        yield 'an integer' => [-65535];
        yield 'text' => ['-65535'];
    }

    /**
     * A statement signed with another algorithm, or that names none, is the format's to verify, and its answer
     * is the answer.
     *
     * @param array<string, mixed> $statement
     */
    #[Test]
    #[DataProvider('provideStatementsTheFormatVerifies')]
    public function aStatementOfAnotherAlgorithmIsVerifiedByTheFormat(array $statement, bool $answer): void
    {
        // Given
        $format = new RecordingAttestationStatementSupport($answer);
        $support = new Rs1RefusingAttestationStatementSupport($format);

        // When
        $valid = $support->isValid('hash', AttestationStatement::createSelf('packed', $statement, EmptyTrustPath::create()), Fixtures::authenticatorData());

        // Then
        static::assertSame($answer, $valid);
        static::assertSame(1, $format->verified);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, bool}>
     */
    public static function provideStatementsTheFormatVerifies(): iterable
    {
        yield 'ES256, accepted by the format' => [['alg' => -7, 'sig' => 'signature'], true];
        yield 'RS256, refused by the format' => [['alg' => -257, 'sig' => 'signature'], false];
        yield 'no algorithm named, as fido-u2f' => [['sig' => 'signature'], true];
    }

    #[Test]
    public function theNameIsTheOneOfTheFormat(): void
    {
        // Given
        $support = new Rs1RefusingAttestationStatementSupport(new RecordingAttestationStatementSupport());

        // When
        $name = $support->name();

        // Then
        static::assertSame('recording', $name);
    }

    #[Test]
    public function aStatementIsLoadedByTheFormat(): void
    {
        // Given
        $format = new RecordingAttestationStatementSupport();
        $support = new Rs1RefusingAttestationStatementSupport($format);

        // When
        $statement = $support->load(['fmt' => 'recording', 'attStmt' => []]);

        // Then
        static::assertSame($format->loaded, $statement);
    }
}
