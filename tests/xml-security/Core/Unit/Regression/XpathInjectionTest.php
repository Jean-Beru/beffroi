<?php

declare(strict_types=1);

namespace Beffroi\Xml\Tests\Core\Unit\Regression;

use Beffroi\Xml\Core\Exception\UnknownId;
use Beffroi\Xml\Tests\Core\Support\Loaded;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 3, GHSA-2g98-f9jv-w8c5, I-9, I-14
 */
final class XpathInjectionTest extends TestCase
{
    /**
     * GHSA-2g98-f9jv-w8c5, I-9
     */
    #[Test]
    #[DataProvider('provideCraftedIdentifiers')]
    public function ghsa2g98f9jvw8c5ACraftedIdentifierIsLookedUpNeverEvaluated(string $identifier): void
    {
        // Given
        $document = Loaded::fixture('behaviour/response-with-assertion.xml');
        static::assertFalse($document->hasId($identifier));

        // Then
        $this->expectException(UnknownId::class);
        $this->expectExceptionMessageIs('No element carries that ID (section 6.2).');

        // When
        $document->elementById($identifier);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCraftedIdentifiers(): iterable
    {
        yield 'a predicate closing and reopening' => ["_assertion')] | //*[@ID='_response"];
        yield 'an alternative node set' => ['_assertion | //saml:Assertion'];
        yield 'a quote' => ["'"];
        yield 'an id() call' => ["xpointer(id('_assertion'))"];
        yield 'a fragment sign' => ['#_assertion'];
    }
}
