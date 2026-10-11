<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Session;

use Beffroi\Core\Application\Session\StoredAuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\TwoFactors;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Predicates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0010: the document the "acr" policy of a tenant is kept as, read back without a connection. A
 * predicate is written under the name it gives itself and read back as the class the wiring holds for that
 * name, so the wiring is an argument and a name nothing wired carries is refused rather than guessed.
 */
final class StoredAuthenticationContextPolicyTest extends TestCase
{
    private StoredAuthenticationContextPolicy $policies;

    protected function setUp(): void
    {
        $this->policies = new StoredAuthenticationContextPolicy(Predicates::wired());
    }

    /**
     * A list and not an object keyed by name: "1" and "2" are names, and a JSON object key that looks
     * like a number comes back as an integer.
     *
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function itWritesTheDocumentAColumnHoldsAPolicyAs(AuthenticationContextPolicy $policy, array $document): void
    {
        // When / Then
        static::assertSame($document, $this->policies->document($policy));
    }

    /**
     * @param array<string, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocuments')]
    public function aPolicyComesBackOutOfItsDocument(AuthenticationContextPolicy $policy, array $document): void
    {
        // When / Then
        static::assertEquals($policy, $this->policies->of($document));
    }

    /**
     * @return iterable<string, array{AuthenticationContextPolicy, array<string, mixed>}>
     */
    public static function provideDocuments(): iterable
    {
        yield 'a policy a tenant configured' => [
            new AuthenticationContextPolicy([
                new AuthenticationContextClass('urn:okta:loa:2fa:any', new TwoFactors()),
                AuthenticationContextClass::singleFactor(),
            ]),
            [
                'classes' => [
                    [
                        'name' => 'urn:okta:loa:2fa:any',
                        'predicate' => 'two_factors',
                    ],
                    [
                        'name' => '1',
                        'predicate' => 'single_factor',
                    ],
                ],
            ],
        ];
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsThatAreNotAPolicy')]
    public function aDocumentThatIsNotAPolicyIsRefused(array $document, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->policies->of($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, string}>
     */
    public static function provideDocumentsThatAreNotAPolicy(): iterable
    {
        yield 'no class at all' => [
            [
                'classes' => [],
            ],
            'An authentication context policy names at least one class.',
        ];
        yield 'a document naming no classes' => [[], 'An authentication context policy names at least one class.'];
        yield 'a class that is a string' => [
            [
                'classes' => ['1'],
            ],
            'The authentication context class must be a JSON object, got string.',
        ];
        yield 'a class naming no predicate' => [
            [
                'classes' => [
                    [
                        'name' => '1',
                    ],
                ],
            ],
            'An authentication context policy lists classes, each a name on a predicate of the provider.',
        ];
        yield 'a numeric name' => [
            [
                'classes' => [
                    [
                        'name' => 1,
                        'predicate' => 'single_factor',
                    ],
                ],
            ],
            'The member "name" must be a string or absent.',
        ];
        yield 'a predicate nothing wired carries' => [
            [
                'classes' => [
                    [
                        'name' => '1',
                        'predicate' => 'attested',
                    ],
                ],
            ],
            'This provider defines no authentication predicate "attested"; it defines phishing_resistant_hardware, phishing_resistant, two_factors, single_factor.',
        ];
    }
}
