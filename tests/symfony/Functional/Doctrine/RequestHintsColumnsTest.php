<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use function array_keys;
use Doctrine\DBAL\Connection;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use Beffroi\Core\Domain\PersonalData\Sealed;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\ClassifiedModel;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;

final class RequestHintsColumnsTest extends DatabaseTestCase
{
    private const string LOGIN_HINT = SealedRows::VALUES['beffroi_interaction']['login_hint'];

    private const string ID_TOKEN_HINT = SealedRows::VALUES['beffroi_interaction']['id_token_hint'];

    /**
     * @var array<string, list<string>> table, then the columns the fixture writes
     */
    private const array SEALED = [
        'beffroi_interaction' => ['login_hint', 'id_token_hint'],
        'beffroi_pushed_authorization_request' => ['parameters'],
    ];

    /**
     * Decision 0011
     */
    #[Test]
    #[DataProvider('provideTables')]
    public function theFixtureWritesEveryColumnTheClassificationDeclaresSealed(string $table): void
    {
        // Given
        $sealed = [];
        foreach (ClassifiedModel::of(self::entityManager())->linesOf($table) as $column => $line) {
            if ($line instanceof Sealed) {
                $sealed[] = $column;
            }
        }
        sort($sealed);

        // When
        $written = self::SEALED[$table];
        sort($written);

        // Then
        static::assertSame($sealed, $written);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTables(): iterable
    {
        foreach (array_keys(self::SEALED) as $table) {
            yield $table => [$table];
        }
    }

    #[Test]
    public function anInteractionIsReadBackWithBothHints(): void
    {
        // Given
        $id = self::interaction();
        self::reload();

        // When
        $found = self::interactions()->find($id);

        // Then
        static::assertInstanceOf(Interaction::class, $found);
        static::assertSame(self::LOGIN_HINT, $found->request->loginHint);
        static::assertSame(self::ID_TOKEN_HINT, $found->request->idTokenHint);
    }

    #[Test]
    public function aRequestThatNamedNobodyHoldsNoHintAtAll(): void
    {
        // Given
        $id = self::interaction(loginHint: null, idTokenHint: null);
        self::reload();

        // When
        $found = self::interactions()->find($id);

        // Then
        static::assertInstanceOf(Interaction::class, $found);
        static::assertNull($found->request->loginHint);
        static::assertNull($found->request->idTokenHint);
        $row = self::rows('beffroi_interaction')[0];
        static::assertNull($row['login_hint']);
        static::assertNull($row['id_token_hint']);
    }

    /**
     * RFC 9126 §2.2
     */
    #[Test]
    public function aPushedRequestIsReadBackWithTheParametersTheClientWrote(): void
    {
        // Given
        $hash = self::pushed();
        self::reload();

        // When
        $found = self::pushedRequests()->findByRequestUriHash($hash);

        // Then
        static::assertInstanceOf(PushedAuthorizationRecord::class, $found);
        static::assertSame(self::LOGIN_HINT, $found->parameters['login_hint'] ?? null);
        static::assertSame(self::ID_TOKEN_HINT, $found->parameters['id_token_hint'] ?? null);
        static::assertSame(['openid', 'profile'], $found->parameters['scope'] ?? null);
    }

    #[Test]
    #[DataProvider('provideSealedColumns')]
    public function theRowHoldsNeitherHint(string $table, string $column): void
    {
        // Given
        self::interaction();
        self::pushed();

        // When
        $stored = self::rows($table)[0][$column];

        // Then
        static::assertNotNull($stored, sprintf('%s.%s holds nothing, so there is nothing to search.', $table, $column));
        foreach ([self::LOGIN_HINT, self::ID_TOKEN_HINT] as $hint) {
            static::assertStringNotContainsString(
                $hint,
                (string) $stored,
                sprintf('%s.%s holds "%s" in the clear.', $table, $column, $hint),
            );
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSealedColumns(): iterable
    {
        foreach (self::SEALED as $table => $columns) {
            foreach ($columns as $column) {
                yield $table . '.' . $column => [$table, $column];
            }
        }
    }

    #[Test]
    public function theRowOfAPushedRequestGivesAwayNoParameterAtAll(): void
    {
        // Given
        self::pushed();

        // When
        $stored = self::rows('beffroi_pushed_authorization_request')[0]['parameters'];

        // Then
        static::assertNotNull($stored);
        static::assertStringNotContainsString('openid', (string) $stored);
        static::assertStringNotContainsString('login_hint', (string) $stored);
    }

    private static function interaction(
        ?string $loginHint = self::LOGIN_HINT,
        ?string $idTokenHint = self::ID_TOKEN_HINT,
    ): string {
        return self::fixture()->interaction(self::client(), $loginHint, $idTokenHint);
    }

    private static function pushed(): string
    {
        return self::fixture()->pushedRequest(self::client());
    }

    private static function fixture(): SealedRows
    {
        return new SealedRows(self::getContainer(), self::tenant(), self::now());
    }

    /**
     * @return list<array<string, string|null>>
     */
    private static function rows(string $table): array
    {
        $rows = RawRows::of(self::connection(), $table, self::SEALED[$table]);
        static::assertCount(1, $rows);

        return $rows;
    }

    private static function interactions(): InteractionRepositoryInterface
    {
        return self::service('test.beffroi.interactions', InteractionRepositoryInterface::class);
    }

    private static function pushedRequests(): PushedAuthorizationRecordRepositoryInterface
    {
        return self::service('test.beffroi.pushed_authorization_requests', PushedAuthorizationRecordRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
