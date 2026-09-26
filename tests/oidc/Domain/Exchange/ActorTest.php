<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Exchange;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Oidc\Domain\Exchange\Actor;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Who acts for the subject of a token (RFC 8693 §4.1): the "act" claim, which nests and is never flattened.
 */
final class ActorTest extends TestCase
{
    /**
     * RFC 8693 §4.1: an actor that received the token from the subject itself is one member.
     */
    #[Test]
    public function oneActorIsWrittenAsItsSubjectAlone(): void
    {
        // Given
        $actor = new Actor(new Subject('gateway'));

        // When / Then
        static::assertSame(
            [
                'sub' => 'gateway',
            ],
            $actor->toClaim(),
        );
    }

    /**
     * RFC 8693 §4.1: "the most recent actor is the outermost", the one it acts through nested inside it.
     */
    #[Test]
    public function aChainIsWrittenWithTheMostRecentActorOutermost(): void
    {
        // Given
        $actor = new Actor(new Subject('backend'), new Actor(new Subject('gateway')));

        // When / Then
        static::assertSame(
            [
                'sub' => 'backend',
                'act' => [
                    'sub' => 'gateway',
                ],
            ],
            $actor->toClaim(),
        );
    }

    /**
     * RFC 8693 §4.1: a second exchange adds its actor around the chain it found.
     */
    #[Test]
    public function anActorActsThroughTheChainItFound(): void
    {
        // Given
        $found = new Actor(new Subject('gateway'));

        // When
        $actor = new Actor(new Subject('backend'))->actingThrough($found);

        // Then
        static::assertSame(
            [
                'sub' => 'backend',
                'act' => [
                    'sub' => 'gateway',
                ],
            ],
            $actor->toClaim(),
        );
    }

    /**
     * RFC 8693 §4.1: read back as it was written, whatever the depth.
     */
    #[Test]
    public function aChainIsReadBackAsItWasWritten(): void
    {
        // Given
        $actor = new Actor(new Subject('outer'), new Actor(new Subject('middle'), new Actor(new Subject('inner'))));

        // When
        $read = Actor::fromClaim($actor->toClaim());

        // Then
        static::assertTrue($read->equals($actor));
    }

    #[Test]
    public function twoChainsOfDifferentLengthsDiffer(): void
    {
        // When / Then
        static::assertFalse(new Actor(new Subject('one'))->equals(new Actor(new Subject('one'), new Actor(new Subject('two')))));
    }

    #[Test]
    public function twoChainsThatNameDifferentActorsDiffer(): void
    {
        // When / Then
        static::assertFalse(
            new Actor(new Subject('one'), new Actor(new Subject('two')))->equals(new Actor(new Subject('one'), new Actor(new Subject('three')))),
        );
    }

    /**
     * RFC 8693 §4.1: a member this provider does not write is not one it believes.
     */
    #[Test]
    public function nothingBesideTheSubjectAndTheChainIsRead(): void
    {
        // When
        $actor = Actor::fromClaim([
            'sub' => 'gateway',
            'client_id' => 'somebody-else',
        ]);

        // Then
        static::assertSame(
            [
                'sub' => 'gateway',
            ],
            $actor->toClaim(),
        );
    }

    /**
     * @param mixed $act what a claim would carry
     */
    #[Test]
    #[DataProvider('provideWhatIsNotAnActClaim')]
    public function itRefusesWhatThisProviderNeverWrote(mixed $act, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        Actor::fromClaim($act);
    }

    /**
     * @return iterable<string, array{mixed, string}>
     */
    public static function provideWhatIsNotAnActClaim(): iterable
    {
        yield 'a string' => ['gateway', 'is a JSON object (RFC 8693 section 4.1)'];
        yield 'no subject' => [
            [
                'client_id' => 'gateway',
            ],
            'names the actor in its "sub" (RFC 8693 section 4.1)',
        ];
        yield 'a subject that is not text' => [
            [
                'sub' => 42,
            ],
            'names the actor in its "sub" (RFC 8693 section 4.1)',
        ];
        yield 'a subject with a space' => [
            [
                'sub' => 'the gateway',
            ],
            'The "sub" of an "act" claim is a subject (OIDC Core section 2)',
        ];
        yield 'a nested actor that is not an object' => [
            [
                'sub' => 'backend',
                'act' => 'gateway',
            ],
            'is a JSON object (RFC 8693 section 4.1)',
        ];
    }
}
