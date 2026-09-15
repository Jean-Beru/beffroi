<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Claims;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PublicSubjectIdentifierResolver;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PublicSubjectIdentifierResolverTest extends TestCase
{
    /**
     * OIDC Core §8 "public": the same subject for every client, the one the core keeps for the user.
     */
    #[Test]
    public function itGivesEveryClientTheSubjectOfTheUser(): void
    {
        $user = Fixtures::user();
        $resolver = new PublicSubjectIdentifierResolver();

        static::assertSame($user->subject, $resolver->resolve($user, Clients::public($user->tenant)));
        static::assertSame($user->subject, $resolver->resolve($user, Clients::public($user->tenant, 'other')));
    }
}
