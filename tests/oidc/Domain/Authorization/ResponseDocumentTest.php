<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use function array_keys;
use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Authorization\ResponseDocument;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * JARM §2.1: the claims of a signed authorization response.
 */
final class ResponseDocumentTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    /**
     * JARM §2.1: every parameter the answer would have carried becomes a claim of its own, and the three
     * of the section are added; "state" is one of the parameters and therefore travels inside.
     */
    #[Test]
    public function everyParameterOfTheAnswerBecomesAClaimBesideTheThreeOfTheSection(): void
    {
        // Given
        $document = new ResponseDocument(
            new Issuer(self::ISSUER),
            'oidc-demo',
            [
                'code' => 'the-code',
                'state' => 'state-of-the-client',
                'iss' => self::ISSUER,
            ],
            new DateTimeImmutable('2026-09-22T10:05:00+00:00'),
        );

        // When
        $claims = $document->claims();

        // Then
        static::assertSame(['code', 'state', 'iss', 'aud', 'exp'], array_keys($claims));
        static::assertSame('the-code', $claims['code']);
        static::assertSame('state-of-the-client', $claims['state']);
        static::assertSame(self::ISSUER, $claims['iss']);
        static::assertSame('oidc-demo', $claims['aud']);
        static::assertSame(1790071500, $claims['exp']);
    }

    /**
     * JARM §2.4: a refusal is the same document, with the error among its parameters.
     */
    #[Test]
    public function aRefusalIsTheSameDocument(): void
    {
        // Given
        $document = new ResponseDocument(
            new Issuer(self::ISSUER),
            'oidc-demo',
            [
                'error' => 'invalid_request',
                'state' => 'state-of-the-client',
            ],
            new DateTimeImmutable('2026-09-22T10:05:00+00:00'),
        );

        // When
        $claims = $document->claims();

        // Then
        static::assertSame(['error', 'state', 'iss', 'aud', 'exp'], array_keys($claims));
        static::assertSame('invalid_request', $claims['error']);
    }

    /**
     * The document names its issuer from the tenant, whatever the answer carried.
     */
    #[Test]
    public function theIssuerIsTheOneOfTheTenant(): void
    {
        // Given
        $document = new ResponseDocument(
            new Issuer(self::ISSUER),
            'oidc-demo',
            [
                'iss' => 'https://elsewhere.example',
            ],
            new DateTimeImmutable('2026-09-22T10:05:00+00:00'),
        );

        // When
        $claims = $document->claims();

        // Then
        static::assertSame(self::ISSUER, $claims['iss']);
    }

    #[Test]
    public function aDocumentWithoutAParameterIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A signed authorization response carries at least one parameter (JARM section 2.1).');

        // When
        new ResponseDocument(new Issuer(self::ISSUER), 'oidc-demo', [], new DateTimeImmutable('2026-09-22T10:05:00+00:00'));
    }
}
