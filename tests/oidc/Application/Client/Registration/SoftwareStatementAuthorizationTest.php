<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementAuthorization;
use Beffroi\Oidc\Application\Client\Registration\SoftwareStatementVerifier;
use Beffroi\Oidc\Bridge\InMemory\InMemorySoftwareStatementReplayGuard;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryCompactJwtReader;
use Beffroi\Oidc\Bridge\JwtLibrary\JwtLibraryJwtKeyVerifier;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\UnauthorizedRegistrationException;
use Beffroi\Oidc\Tests\Fixture\Policies;
use Beffroi\Oidc\Tests\Fixture\SoftwareStatements;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 7591 §2.3, §3.1.1, Decision 0009
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
     * Decision 0009
     */
    #[Test]
    public function itNamesItself(): void
    {
        // When / Then
        static::assertSame('software_statement', $this->authorization->name());
    }

    /**
     * RFC 7591 §3.1.1
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
        $authorized = $this->authorization->authorize($this->tenant, $request, Policies::attested([SoftwareStatements::authority()]));

        // Then
        static::assertCount(1, $authorized->inFront);
        static::assertSame('Invoice reader, attested', $authorized->inFront[0]->members()['client_name']);
    }

    /**
     * Decision 0043
     */
    #[Test]
    public function aStatementGivesTheClientNoMemberOfTheDeployment(): void
    {
        // Given
        $request = new RegistrationRequest([
            'software_statement' => SoftwareStatements::statement((string) $this->tenant->issuer, Fixtures::now()),
        ]);

        // When
        $authorized = $this->authorization->authorize($this->tenant, $request, Policies::attested([SoftwareStatements::authority()]));

        // Then
        static::assertNull($authorized->granted);
    }

    /**
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
