<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit;

use function array_diff;
use function array_keys;
use Beffroi\Saml2\Model\Tests\Support\Traceability;
use function dirname;
use function implode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.7
 */
final class TraceabilityTest extends TestCase
{
    private Traceability $traceability;

    protected function setUp(): void
    {
        $this->traceability = new Traceability(dirname(__DIR__, 3) . '/src/saml2-model/spec/model.md', __DIR__);
    }

    /**
     * Section 4, M-1 to M-18
     */
    #[Test]
    public function everyInvariantIsCitedByATest(): void
    {
        // Given
        $invariants = $this->traceability->invariants();
        static::assertCount(18, $invariants);

        // When
        $uncited = array_diff($invariants, $this->traceability->citedInvariants());

        // Then
        static::assertSame([], $uncited, 'Invariants no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.2
     */
    #[Test]
    public function everyRowOfTheHostileCorpusIsCitedByATest(): void
    {
        // Given
        $rows = $this->traceability->tableRows('### 9.2 Hostile corpus');
        static::assertCount(51, $rows);

        // When
        $uncited = array_diff(array_keys($rows), $this->traceability->citedRows('9.2'));

        // Then
        static::assertSame([], $uncited, 'Rows of section 9.2 no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.3
     */
    #[Test]
    public function everyRowOfTheBehaviourCorpusIsCitedByATest(): void
    {
        // Given
        $rows = $this->traceability->tableRows('### 9.3 Behaviour corpus');
        static::assertCount(26, $rows);

        // When
        $uncited = array_diff(array_keys($rows), $this->traceability->citedRows('9.3'));

        // Then
        static::assertSame([], $uncited, 'Rows of section 9.3 no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.7
     */
    #[Test]
    public function everyCitedRowExists(): void
    {
        // Given
        $hostile = array_keys($this->traceability->tableRows('### 9.2 Hostile corpus'));
        $behaviour = array_keys($this->traceability->tableRows('### 9.3 Behaviour corpus'));

        // When
        $unknown = [
            ...array_diff($this->traceability->citedRows('9.2'), $hostile),
            ...array_diff($this->traceability->citedRows('9.3'), $behaviour),
        ];

        // Then
        static::assertSame([], $unknown, 'Rows cited that the tables do not have: ' . implode(', ', $unknown));
    }
}
