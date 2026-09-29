<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use DateInterval;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Heidi\Oidc\Application\Client\Registration\SoftwareStatementVerifier;
use Heidi\Oidc\Bridge\InMemory\InMemorySoftwareStatementReplayGuard;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Heidi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;
use Heidi\Oidc\Tests\Fixture\Policies;
use Heidi\Oidc\Tests\Fixture\SoftwareStatements;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 7591 §2.3, the fourth mode of decision 0009: the one that reads the body rather than the header, and
 * the only one that puts anything in front of the members the client sent (§3.1.1).
 */
final class SoftwareStatementAuthorizationTest extends TestCase
{
    private Tenant $tenant;

    private SoftwareStatementAuthorization $authorization;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->authorization = new SoftwareStatementAuthorization(
            new SoftwareStatementVerifier(
                new JwtLibraryCompactJwtReader(),
                new JwtLibraryJwtKeyVerifier(Algorithms::all()->manager()),
                new InMemorySoftwareStatementReplayGuard(),
                new DateInterval('PT5M'),
                new DateInterval('PT30S'),
            ),
            new MockClock(Fixtures::now()),
        );
    }

    /**
     * Decision 0009: a mode is compared to a literal in the class that is that mode and nowhere else.
     */
    #[Test]
    public function itNamesItself(): void
    {
        // When / Then
        static::assertSame('software_statement', $this->authorization->name());
    }

    /**
     * §3.1.1: what a statement says outranks what the client sent, which is the same decision as trusting
     * it, so the class that trusts it is the class that answers with the source that wins.
     */
    #[Test]
    public function itPutsTheStatementInFrontOfWhatTheClientSent(): void
    {
        // Given
        $statement = SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now());
        $request = new RegistrationRequest([
            'software_statement' => $statement,
            'client_name' => 'what the caller typed',
        ]);

        // When
        $sources = $this->authorization->authorize($this->tenant, $request, Policies::attested([SoftwareStatements::authority()]));

        // Then
        static::assertCount(1, $sources);
        static::assertSame('Invoice reader, attested', $sources[0]->members()['client_name']);
    }

    /**
     * A request that carries no statement at all presents nothing this mode acts on, which reads as a
     * request that carries no credential: it is not a statement that failed to verify.
     *
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideBodiesThatCarryNoStatement')]
    public function itRefusesARequestThatCarriesNoStatement(array $members): void
    {
        // Then
        $this->expectException(UnauthorizedRegistrationException::class);

        // When
        $this->authorization->authorize($this->tenant, new RegistrationRequest($members), Policies::attested([SoftwareStatements::authority()]));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideBodiesThatCarryNoStatement(): iterable
    {
        yield 'nothing at all' => [[]];
        yield 'a member of another name' => [[
            'client_name' => 'what the caller typed',
        ]];
        yield 'a statement that carries nothing' => [[
            'software_statement' => '',
        ]];
        yield 'a statement that is no string' => [[
            'software_statement' => ['not', 'a', 'string'],
        ]];
    }

    /**
     * A body that is no JSON object carries no members at all, and says so where every other caller of the
     * request is told it.
     */
    #[Test]
    public function itRefusesABodyThatIsNoJsonObject(): void
    {
        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('The body of a registration request is a JSON object');

        // When
        $this->authorization->authorize($this->tenant, new RegistrationRequest(), Policies::attested([SoftwareStatements::authority()]));
    }
}
