<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_keys;
use Doctrine\DBAL\Connection;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\RawRows;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\Sealed;
use Heidi\Bundle\Tests\Functional\Doctrine\PersonalData\SchemaColumns;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use Heidi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;

/**
 * What a request keeps of the person it asks for, sealed and read back (decisions 0011 and 0018): the two
 * hints a client may send, and the parameters of a request it pushed.
 *
 * **Three columns over two tables, and no index**, nothing looking a row up by a hint: an interaction is
 * found by its identifier and a pushed request by the digest of the reference it was answered with, which
 * is its primary key. That the whole of a parked request still comes back is
 * `DoctrineInteractionRepositoryTest`, which asserts both hints among every other parameter and which runs
 * against this mapping; what is written here is what that test cannot say, which is what the rows hold.
 *
 * The two hints are columns of `heidi_interaction` and of no other table, `AuthorizationRequest` being an
 * embeddable that one entity embeds with no column prefix. That is also why the walk of the schema now
 * holds a sealed column to its own table: an embeddable fixes the type of each of its fields once for the
 * whole model, so a second entity embedding this object would seal those columns under a scope that is not
 * its table's (`SchemaClassificationTest`).
 */
final class RequestHintsColumnsTest extends DatabaseTestCase
{
    private const string LOGIN_HINT = 'ada@example.org';

    private const string ID_TOKEN_HINT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZGEtc3ViamVjdCJ9.sig';

    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * The personal data a request keeps, by the column each one lands in, over the two tables.
     *
     * @var array<string, list<string>> table, then the columns the fixture writes
     */
    private const array SEALED = [
        'heidi_interaction' => ['login_hint', 'id_token_hint'],
        'heidi_pushed_authorization_request' => ['parameters'],
    ];

    /**
     * The fixture writes every column the classification of the schema declares sealed on these two
     * tables, and no other: a column sealed without a value written here would be asserted against
     * nothing, and the walk of the schema is what says which those are (SchemaColumns, decision 0011).
     */
    #[Test]
    #[DataProvider('provideTables')]
    public function theFixtureWritesEveryColumnTheClassificationDeclaresSealed(string $table): void
    {
        // Given
        $sealed = [];
        foreach (SchemaColumns::all()[$table] as $column => $line) {
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

    /**
     * The two hints come back as the client sent them, the encrypted type decorating the type the column
     * had, and the request they belong to is the embeddable of the interaction that parks it.
     */
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

    /**
     * A sealed column that accepts a null holds a null and not the envelope of an empty string: a request
     * that named nobody has no hint, and a hint read back as an empty string would be a hint.
     */
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
        $row = self::rows('heidi_interaction')[0];
        static::assertNull($row['login_hint']);
        static::assertNull($row['id_token_hint']);
    }

    /**
     * RFC 9126 §2.2: the parameters are kept as the client wrote them, so the hints are in there word for
     * word, and they come back as the client wrote them too.
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

    /**
     * Column by column over the two tables, which is the point of the data provider: a column that
     * stopped sealing fails on its own line.
     */
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

    /**
     * And what else that row stops holding: the parameters are the ciphertext of a JSON document now, so
     * the column gives away neither the scope the client asked for nor the address it sent it to, where
     * before it gave away every parameter of the request.
     */
    #[Test]
    public function theRowOfAPushedRequestGivesAwayNoParameterAtAll(): void
    {
        // Given
        self::pushed();

        // When
        $stored = self::rows('heidi_pushed_authorization_request')[0]['parameters'];

        // Then
        static::assertNotNull($stored);
        static::assertStringNotContainsString('openid', (string) $stored);
        static::assertStringNotContainsString('login_hint', (string) $stored);
    }

    private static function interaction(
        ?string $loginHint = self::LOGIN_HINT,
        ?string $idTokenHint = self::ID_TOKEN_HINT,
    ): string {
        $client = self::client();
        $request = new AuthorizationRequest(
            $client,
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid'), new Scope('profile')]),
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
            loginHint: $loginHint,
            idTokenHint: $idTokenHint,
        );
        $id = Secrets::draw();
        self::interactions()->save(new Interaction($id, self::tenant(), $request, 'en', self::now(), self::now()->modify('+10 minutes')));

        return $id;
    }

    private static function pushed(): string
    {
        $hash = DrawnSecret::digestOf(Secrets::draw());
        self::pushedRequests()
            ->save(new PushedAuthorizationRecord(
                $hash,
                self::client(),
                [
                    'response_type' => 'code',
                    'scope' => ['openid', 'profile'],
                    'login_hint' => self::LOGIN_HINT,
                    'id_token_hint' => self::ID_TOKEN_HINT,
                ],
                self::now(),
                self::now()->modify('+90 seconds'),
            ));

        return $hash;
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
        return self::service('test.heidi.interactions', InteractionRepositoryInterface::class);
    }

    private static function pushedRequests(): PushedAuthorizationRecordRepositoryInterface
    {
        return self::service('test.heidi.pushed_authorization_requests', PushedAuthorizationRecordRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::entityManager()->getConnection();
    }
}
