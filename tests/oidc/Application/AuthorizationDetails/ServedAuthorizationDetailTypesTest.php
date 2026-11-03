<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\AuthorizationDetails;

use Beffroi\Oidc\Application\AuthorizationDetails\ServedAuthorizationDetailTypes;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetailTypeInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use Beffroi\Oidc\Tests\Fixture\InventedAuthorizationDetailType;
use function is_string;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The types of authorization detail the wiring gave the provider (RFC 9396 §2), the one source of truth
 * over them: what a request may ask for, what a client may register and what the document announces are
 * this list read.
 */
final class ServedAuthorizationDetailTypesTest extends TestCase
{
    /**
     * RFC 9396 §10: a type names itself, so what is announced is what is wired, in the order it is wired.
     */
    #[Test]
    public function theTypesAreTheWiredOnesInTheOrderTheyAreWired(): void
    {
        // Given
        $types = AuthorizationDetailTypes::served([
            new InventedAuthorizationDetailType('payment_initiation'),
            new InventedAuthorizationDetailType(),
        ]);

        // When / Then
        static::assertSame(['payment_initiation', AuthorizationDetailTypes::INVENTED], $types->servedAuthorizationDetailTypes());
    }

    /**
     * A deployment wired with none serves none, which is what the provider ships: no type of detail is
     * universal.
     */
    #[Test]
    public function aProviderWiredWithNoTypeServesNone(): void
    {
        // When / Then
        static::assertSame([], AuthorizationDetailTypes::none()->servedAuthorizationDetailTypes());
    }

    /**
     * Two classes answering for one "type" is a wiring where what a detail means depends on an order
     * nobody wrote down.
     */
    #[Test]
    public function twoClassesCannotAnswerForOneType(): void
    {
        // Given
        $types = AuthorizationDetailTypes::served([new InventedAuthorizationDetailType(), new InventedAuthorizationDetailType()]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Two classes answer for the authorization detail type "account_information".');

        // When
        $types->servedAuthorizationDetailTypes();
    }

    /**
     * RFC 9396 §2: the parameter is read into the details the wired types made of it.
     */
    #[Test]
    public function itReadsTheParameterIntoTheDetailsOfTheWiredTypes(): void
    {
        // Given
        $types = AuthorizationDetailTypes::served();

        // When
        $details = $types->fromJson(AuthorizationDetailTypes::parameter('acct-4711', ['read', 'write']));

        // Then
        static::assertCount(1, $details);
        static::assertSame(
            [
                [
                    'type' => AuthorizationDetailTypes::INVENTED,
                    'account' => 'acct-4711',
                    'actions' => ['read', 'write'],
                ],
            ],
            $details->toClaim(),
        );
    }

    /**
     * The type is the only place that knows what a detail of it means, so it is the only place that says
     * what a page shows of one.
     */
    #[Test]
    public function aDetailCarriesWhatItsTypeSaysAPageShowsOfIt(): void
    {
        // Given
        $types = AuthorizationDetailTypes::served();

        // When
        $details = $types->fromJson(AuthorizationDetailTypes::parameter('acct-4711', ['read', 'write']));

        // Then
        static::assertSame(
            [
                'account' => 'acct-4711',
                'actions' => 'read, write',
            ],
            $details->all[0]->rendering,
        );
    }

    /**
     * RFC 9396 §2: a detail of a type this provider serves is one that type accepted, in the order that
     * type built it, whatever order the request wrote it in.
     */
    #[Test]
    public function theMembersAreTheOnesTheTypeBuiltAndNotTheOnesTheRequestWrote(): void
    {
        // Given
        $types = AuthorizationDetailTypes::served();
        $written = '[{"actions":["read"],"account":"acct-4711","type":"account_information"}]';

        // When
        $details = $types->fromJson($written);

        // Then
        static::assertTrue($details->equals(AuthorizationDetailTypes::details('acct-4711', ['read'])));
    }

    /**
     * RFC 9396 §7: a token carries what a request asked for, so what is refused of one is refused of the
     * other, and the claim is read back through the same types.
     */
    #[Test]
    public function itReadsTheClaimOfATokenBackThroughTheSameTypes(): void
    {
        // Given
        $types = AuthorizationDetailTypes::served();
        $details = AuthorizationDetailTypes::details('acct-4711', ['read']);

        // When / Then
        static::assertTrue($types->fromClaim($details->toClaim())->equals($details));
    }

    /**
     * RFC 9396 §5: a malformed array, an object naming no type, a type nobody serves and a detail its own
     * type refuses are all refused, none of them read as something else.
     */
    #[Test]
    #[DataProvider('provideRefusedParameters')]
    public function whatIsNotAnAuthorizationDetailsIsRefused(string $json, string $message): void
    {
        // Given
        $types = AuthorizationDetailTypes::served();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $types->fromJson($json);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusedParameters(): iterable
    {
        yield 'not JSON' => ['[{', 'An authorization_details parameter is valid JSON (RFC 9396 section 2).'];
        yield 'a JSON object' => [
            '{"type":"account_information"}',
            'An authorization_details is a JSON array of objects (RFC 9396 section 2).',
        ];
        yield 'a JSON string' => ['"account_information"', 'An authorization_details is a JSON array of objects (RFC 9396 section 2).'];
        yield 'an empty array' => ['[]', 'A set of authorization details holds at least one detail (RFC 9396 section 2).'];
        yield 'an element that is not an object' => [
            '["account_information"]',
            'Every element of an authorization_details is a JSON object (RFC 9396 section 2).',
        ];
        yield 'an element naming no type' => [
            '[{"account":"acct-4711"}]',
            'Every element of an authorization_details names its type in a "type" member (RFC 9396 section 2).',
        ];
        yield 'an element whose type is not a string' => [
            '[{"type":17}]',
            'Every element of an authorization_details names its type in a "type" member (RFC 9396 section 2).',
        ];
        yield 'a type nobody serves' => [
            '[{"type":"payment_initiation","account":"acct-4711"}]',
            'The authorization detail type "payment_initiation" is not one this provider serves; it serves account_information.',
        ];
        yield 'a detail its own type refuses' => [
            '[{"type":"account_information","actions":["read"]}]',
            'A detail of the type "account_information" names an account in a non-empty "account" member.',
        ];
        // OIDC Core §5.5 reads a claims request the same way: a name made of digits decoded as an integer
        // key, and it names nothing
        yield 'a member whose name is made of digits' => [
            '[{"type":"account_information","0":"acct-4711"}]',
            'The members of an authorization detail of the type "account_information" are named, and a name made of digits is not a name (RFC 9396 section 2).',
        ];
    }

    /**
     * A provider wired with no type names none in its refusal, rather than an empty list a client would
     * read as something else.
     */
    #[Test]
    public function aProviderWiredWithNoTypeSaysSoWhenItRefusesOne(): void
    {
        // Given
        $types = AuthorizationDetailTypes::none();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The authorization detail type "account_information" is not one this provider serves; it serves none.');

        // When
        $types->fromJson(AuthorizationDetailTypes::parameter());
    }

    /**
     * RFC 9396 §2: a type the provider gains is a class added and a line in the wiring, and no production
     * class edited. This test invents one that nothing else knows about.
     */
    #[Test]
    public function aTypeNobodyWroteAClassForIsServedByAddingOne(): void
    {
        // Given
        $invented = new class implements AuthorizationDetailTypeInterface {
            public function type(): string
            {
                return 'urn:example:parking-permit';
            }

            public function of(array $members): AuthorizationDetail
            {
                $plate = $members['plate'] ?? null;
                if (! is_string($plate) || $plate === '') {
                    throw new InvalidArgumentException('A parking permit names the plate it is for.');
                }

                return new AuthorizationDetail(
                    $this->type(),
                    [
                        'plate' => $plate,
                    ],
                    [
                        'plate' => $plate,
                    ],
                );
            }
        };
        $types = new ServedAuthorizationDetailTypes([$invented]);

        // When
        $details = $types->fromJson('[{"type":"urn:example:parking-permit","plate":"AB-123-CD"}]');

        // Then
        static::assertSame(['urn:example:parking-permit'], $types->servedAuthorizationDetailTypes());
        static::assertSame(
            [
                [
                    'type' => 'urn:example:parking-permit',
                    'plate' => 'AB-123-CD',
                ],
            ],
            $details->toClaim(),
        );
        static::assertSame(
            [
                'plate' => 'AB-123-CD',
            ],
            $details->all[0]->rendering,
        );
    }
}
