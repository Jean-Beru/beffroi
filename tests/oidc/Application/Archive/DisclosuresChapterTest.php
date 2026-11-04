<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Archive;

use function array_column;
use function array_map;
use function array_unique;
use function array_values;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Archive\DisclosuresChapter;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDisclosures;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class DisclosuresChapterTest extends TestCase
{
    #[Test]
    public function aLineSaysWhichApplicationWasGivenWhatAndWhen(): void
    {
        // Given
        $user = Fixtures::user();
        $disclosures = new InMemoryDisclosures();
        $disclosures->record(self::disclosure($user, 'oidc-demo', ['openid', 'email']));

        // When
        $lines = new DisclosuresChapter($disclosures)->of($user);

        // Then
        static::assertSame(
            [
                [
                    'client_id' => 'oidc-demo',
                    'act' => TokensIssued::NAME,
                    'handed_over_at' => Fixtures::now()->format('Y-m-d\TH:i:sP'),
                    'scopes' => ['openid', 'email'],
                    'claims' => [
                        'userinfo' => ['email'],
                        'id_token' => [],
                    ],
                    'authorization_details' => null,
                    'token_shape' => 'jwt',
                ],
            ],
            $lines,
        );
    }

    #[Test]
    public function whatWasGivenOfSomebodyElseIsNotRead(): void
    {
        // Given
        $alice = Fixtures::user();
        $bob = Fixtures::user(username: 'bob', subject: 'bob-subject');
        $disclosures = new InMemoryDisclosures();
        $disclosures->record(self::disclosure($bob, 'oidc-demo', ['openid']));

        // When / Then
        static::assertSame([], new DisclosuresChapter($disclosures)->of($alice));
    }

    #[Test]
    public function aRegisterLongerThanOnePageIsReadWhole(): void
    {
        // Given
        $user = Fixtures::user();
        $disclosures = new InMemoryDisclosures();
        for ($written = 0; $written < (DisclosuresChapter::READ_AT_ONCE + 3); ++$written) {
            $disclosures->record(self::disclosure($user, 'oidc-demo', ['openid']));
        }

        // When
        $lines = new DisclosuresChapter($disclosures)->of($user);

        // Then
        static::assertCount(DisclosuresChapter::READ_AT_ONCE + 3, $lines);
        static::assertSame(['oidc-demo'], array_values(array_unique(array_map(self::string(...), array_column($lines, 'client_id')))));
    }

    private static function string(mixed $value): string
    {
        static::assertIsString($value);

        return $value;
    }

    /**
     * @param list<string> $scopes
     */
    private static function disclosure(User $user, string $clientId, array $scopes): Disclosure
    {
        return new Disclosure(
            Uuid::v7(),
            $user->tenant,
            $user->subject,
            $clientId,
            TokensIssued::NAME,
            Fixtures::now(),
            new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $scopes)),
            new ClaimsRequest([
                'email' => new ClaimRequest(),
            ]),
            null,
            'jwt',
        );
    }
}
