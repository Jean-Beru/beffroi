<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Doctrine\PersonalData;

use Beffroi\Bundle\Doctrine\PersonalData\BlindIndexedColumns;
use Beffroi\Bundle\Doctrine\PersonalData\EncryptedColumnTypes;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\BlindIndex;
use Symfony\Component\KeyManagement\Test\InMemoryKms;

/**
 * Decision 0011: what of a value is actually indexed is a rule of the column and not of the call sites,
 * because an index derived on one projection and searched on another silently matches nothing.
 */
final class BlindIndexedColumnsTest extends TestCase
{
    /**
     * A username is indexed byte for byte: folding its case would be a rule of the identity model, which
     * trims a username and nothing more, and not a rule of an index.
     */
    #[Test]
    public function aUsernameDifferingOnlyByItsCaseIsADifferentTag(): void
    {
        // Given
        $index = self::index('username');

        // When / Then
        static::assertNotSame($index->of('alice'), $index->of('Alice'));
    }

    /**
     * RFC 5321 §2.4: the domain of an address is case-insensitive, while the local part is the business of
     * the receiving server and case-sensitive to everyone else. So two addresses that differ only by the
     * case of their domain share a tag, and two that differ by their local part do not.
     */
    #[Test]
    public function anAddressDifferingOnlyByTheCaseOfItsDomainIsTheSameTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertSame($index->of('Ada@Example.org'), $index->of('Ada@EXAMPLE.ORG'));
    }

    /**
     * RFC 5321 §2.4: the local part is case-sensitive, so the projection leaves it alone.
     */
    #[Test]
    public function anAddressDifferingByItsLocalPartIsADifferentTag(): void
    {
        // Given
        $index = self::index('email');

        // When / Then
        static::assertNotSame($index->of('Ada@example.org'), $index->of('ada@example.org'));
    }

    /**
     * One index key per tenant, so the two columns of one tenant derive their tags under one key: a
     * username that happens to be an address and that address share a tag. The columns are distinct and no
     * query confuses them, and this is the fact rather than a defect (decision 0011).
     */
    #[Test]
    public function theTwoColumnsOfOneTenantDeriveTheirTagsUnderOneKey(): void
    {
        // Given
        $kms = new InMemoryKms();
        $wrapped = $kms->generateDataKey('acme.blind_index')->wrapped;

        // When
        $username = BlindIndexedColumns::of(User::class, 'username')->index($kms, $wrapped);
        $email = BlindIndexedColumns::of(User::class, 'email')->index($kms, $wrapped);

        // Then
        static::assertSame($username->of('ada@example.org'), $email->of('ada@example.org'));
    }

    /**
     * A query that asks for a column no index is declared on is a query that would match nothing, so it is
     * refused where it is written rather than answered with an empty result.
     */
    #[Test]
    public function aColumnNoIndexIsDeclaredOnIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('No blind index is declared on "Beffroi\Core\Domain\Identity\User::$phoneNumber", so nothing can be searched by it.');

        // When
        BlindIndexedColumns::of(User::class, 'phoneNumber');
    }

    /**
     * The scope the index key is minted under is no family of columns, so the two cannot share a store and
     * the index key cannot retire with them (decision 0018).
     */
    #[Test]
    public function theScopeOfTheIndexKeyIsNoFamilyOfColumns(): void
    {
        // When / Then
        static::assertArrayNotHasKey(BlindIndexedColumns::SCOPE, EncryptedColumnTypes::FAMILIES);
    }

    private static function index(string $property): BlindIndex
    {
        $kms = new InMemoryKms();

        return BlindIndexedColumns::of(User::class, $property)->index($kms, $kms->generateDataKey('acme.blind_index')->wrapped);
    }
}
