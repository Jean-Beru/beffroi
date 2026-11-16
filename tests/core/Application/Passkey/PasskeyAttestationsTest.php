<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Passkey;

use Beffroi\Core\Application\Passkey\PasskeyAttestations;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\AttestationAuthority;
use Beffroi\Core\Tests\Fixture\AttestationPolicies;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0046
 */
final class PasskeyAttestationsTest extends TestCase
{
    private const string AAGUID = 'cb69481e-8ff7-4039-93ec-0a2729a154a8';

    private PasskeyAttestations $attestations;

    protected function setUp(): void
    {
        $this->attestations = AttestationPolicies::wired();
    }

    #[Test]
    public function theConfigurationNamesThePolicyAndWhatItReads(): void
    {
        // Given
        $root = AttestationAuthority::create()->rootCertificate();
        $own = AttestationAuthority::create()->rootCertificate();

        // When
        $attestation = $this->attestations->named('enterprise', [$root], [$own], [self::AAGUID => '2027-03-31']);

        // Then
        static::assertSame('enterprise', $attestation->policy->name());
        static::assertSame($root, $attestation->roots[0]->pem);
        static::assertSame($own, $attestation->ownRoots[0]->pem);
        static::assertSame(self::AAGUID, $attestation->modelsUnderAlert[0]->aaguid->toRfc4122());
        static::assertSame('2027-03-31', $attestation->modelsUnderAlert[0]->day());
    }

    #[Test]
    public function aPolicyNothingWiredCarriesIsRefusedNamingTheWiredOnes(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This provider wires no passkey attestation policy "indirect"; it wires none, direct, enterprise.');

        // When
        $this->attestations->named('indirect');
    }

    #[Test]
    public function aRootThatIsNoCertificateAuthorityIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is the certificate of no certificate authority');

        // When
        $this->attestations->named('enterprise', [AttestationAuthority::create()->attest()->pem]);
    }

    /**
     * @param array<array-key, mixed> $roots
     * @param array<array-key, mixed> $models
     */
    #[Test]
    #[DataProvider('provideListsOfAnotherShape')]
    public function aListOfAnotherShapeIsRefused(array $roots, array $models, string $refusal): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($refusal);

        // When
        $this->attestations->named('direct', $roots, [], $models);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, array<array-key, mixed>, string}>
     */
    public static function provideListsOfAnotherShape(): iterable
    {
        yield 'a root that is no string' => [[42], [], 'A root of passkey attestations is a certificate in PEM.'];
        yield 'a day that is no string' => [[], [self::AAGUID => 20270331], 'A model under a security alert is admitted until a day, written as "2027-03-31".'];
    }

    #[Test]
    public function anAttestationIsReadBackFromTheDocumentItWasWrittenAs(): void
    {
        // Given
        $attestation = $this->attestations->named(
            'enterprise',
            [AttestationAuthority::create()->rootCertificate()],
            [AttestationAuthority::create()->rootCertificate()],
            [self::AAGUID => '2027-03-31'],
        );

        // When
        $read = $this->attestations->of($this->attestations->document($attestation));

        // Then
        static::assertTrue($read->equals($attestation));
    }

    #[Test]
    public function theDocumentOfATenantThatAsksForNothingIsTheDefaultOfTheColumn(): void
    {
        // When / Then
        static::assertSame(
            [
                'policy' => 'none',
                'roots' => [],
                'own_roots' => [],
                'models_under_alert' => [],
            ],
            $this->attestations->document($this->attestations->named('none')),
        );
    }

    /**
     * @param array<array-key, mixed> $document
     */
    #[Test]
    #[DataProvider('provideDocumentsOfAnotherShape')]
    public function aDocumentOfAnotherShapeIsRefused(array $document): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->attestations->of($document);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideDocumentsOfAnotherShape(): iterable
    {
        yield 'no policy' => [[]];
        yield 'a policy nothing wired carries' => [['policy' => 'indirect']];
        yield 'roots that are no list' => [['policy' => 'direct', 'roots' => 'pem']];
        yield 'a model without its day' => [['policy' => 'direct', 'models_under_alert' => [['aaguid' => self::AAGUID]]]];
        yield 'a model without its AAGUID' => [['policy' => 'direct', 'models_under_alert' => [['until' => '2027-03-31']]]];
    }
}
