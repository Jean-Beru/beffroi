<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use function array_keys;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClaimsRequestTest extends TestCase
{
    private const string SPECIFICATION_EXAMPLE = '{
        "userinfo": {
            "given_name": {"essential": true},
            "nickname": null,
            "email": {"essential": true},
            "email_verified": {"essential": true},
            "picture": null,
            "http://example.info/claims/groups": null
        },
        "id_token": {
            "auth_time": {"essential": true},
            "acr": {"values": ["urn:mace:incommon:iap:silver"]}
        }
    }';

    /**
     * OIDC Core §5.5, the example of the specification: the "userinfo" member, in order, with a claim
     * that is null and essential claims.
     */
    #[Test]
    public function itReadsTheUserinfoMemberOfTheExampleOfTheSpecification(): void
    {
        // When
        $claims = ClaimsRequest::fromJson(self::SPECIFICATION_EXAMPLE);

        // Then
        static::assertSame(
            ['given_name', 'nickname', 'email', 'email_verified', 'picture', 'http://example.info/claims/groups'],
            array_keys($claims->userinfo),
        );
        static::assertEquals(new ClaimRequest(true), $claims->userinfo['given_name']);
        static::assertEquals(new ClaimRequest(), $claims->userinfo['nickname']);
        static::assertFalse($claims->userinfo['nickname']->essential);
        static::assertFalse($claims->isEmpty());
    }

    /**
     * OIDC Core §5.5, the example of the specification: the "id_token" member, with a claim with a set of values.
     */
    #[Test]
    public function itReadsTheIdTokenMemberOfTheExampleOfTheSpecification(): void
    {
        // When
        $claims = ClaimsRequest::fromJson(self::SPECIFICATION_EXAMPLE);

        // Then
        static::assertSame(['auth_time', 'acr'], array_keys($claims->idToken));
        static::assertEquals(new ClaimRequest(false, null, ['urn:mace:incommon:iap:silver']), $claims->idToken['acr']);
    }

    /**
     * OIDC Core §5.5.1: "value" requests a particular value; it is a JSON scalar kept as sent, so a
     * boolean stays a boolean and a number stays a number.
     */
    #[Test]
    public function itKeepsTheRequestedValueAsSent(): void
    {
        // When
        $claims = ClaimsRequest::fromJson('{"id_token": {"sub": {"value": "248289761001"}, "email_verified": {"value": true}, "updated_at": {"values": [1, 2.5]}}}');

        // Then
        static::assertSame('248289761001', $claims->idToken['sub']->value);
        static::assertTrue($claims->idToken['email_verified']->value);
        static::assertSame([1, 2.5], $claims->idToken['updated_at']->values);
    }

    /**
     * OIDC Core §5.5: members that are not understood are ignored.
     */
    #[Test]
    public function itIgnoresWhatItDoesNotUnderstand(): void
    {
        // When
        $claims = ClaimsRequest::fromJson('{"userinfo": null, "other": {"deep": {"deeper": [1]}}, "id_token": {"sub": {"essential": false, "extra": "ignored"}}}');

        // Then
        static::assertSame([], $claims->userinfo);
        static::assertEquals(new ClaimRequest(false), $claims->idToken['sub']);
    }

    /**
     * OIDC Core §5.5: an empty object or an absent member asks for nothing.
     */
    #[Test]
    #[DataProvider('provideRequestsAskingForNothing')]
    public function aRequestWithoutClaimsIsEmpty(string $json): void
    {
        // When / Then
        static::assertTrue(ClaimsRequest::fromJson($json)->isEmpty());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRequestsAskingForNothing(): iterable
    {
        yield 'empty object' => ['{}'];
        yield 'empty members' => ['{"userinfo": {}, "id_token": {}}'];
    }

    #[Test]
    #[DataProvider('provideRequestsAskingForOneClaim')]
    public function aRequestWithOneClaimIsNotEmpty(string $json): void
    {
        // When / Then
        static::assertFalse(ClaimsRequest::fromJson($json)->isEmpty());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRequestsAskingForOneClaim(): iterable
    {
        yield 'userinfo' => ['{"userinfo": {"email": null}}'];
        yield 'id_token' => ['{"id_token": {"email": null}}'];
    }

    /**
     * OIDC Core §5.5 and §5.5.1: a member that is understood but malformed is refused, and "essential" is
     * a JSON boolean, never a string that looks like one.
     */
    #[Test]
    #[DataProvider('provideMalformedRequests')]
    public function itRefusesAMalformedRequest(string $json, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        ClaimsRequest::fromJson($json);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedRequests(): iterable
    {
        yield 'not JSON' => ['{', 'not valid JSON'];
        yield 'too deep' => ['{"userinfo": {"acr": {"values": [[1]]}}}', 'not valid JSON'];
        yield 'a JSON string' => ['"userinfo"', 'JSON object'];
        yield 'a JSON list' => ['[null]', 'JSON object'];
        yield 'userinfo is a string' => ['{"userinfo": "email"}', '"userinfo" member'];
        yield 'id_token is a list' => ['{"id_token": ["sub"]}', '"id_token" member'];
        yield 'empty claim name' => ['{"userinfo": {"": null}}', 'claim name'];
        yield 'claim name made of digits' => ['{"userinfo": {"123": null}}', 'claim name'];
        yield 'claim is a string' => ['{"userinfo": {"email": "essential"}}', 'null or a JSON object'];
        yield 'claim is a list' => ['{"userinfo": {"email": [true]}}', 'null or a JSON object'];
        yield 'essential is a string' => ['{"userinfo": {"email": {"essential": "true"}}}', 'JSON boolean'];
        yield 'essential is a number' => ['{"userinfo": {"email": {"essential": 1}}}', 'JSON boolean'];
        yield 'value is an object' => ['{"id_token": {"sub": {"value": {"a": 1}}}}', '"value" member'];
        yield 'values is a string' => ['{"id_token": {"acr": {"values": "silver"}}}', '"values" member'];
        yield 'values is empty' => ['{"id_token": {"acr": {"values": []}}}', '"values" member'];
        yield 'values is an object' => ['{"id_token": {"acr": {"values": {"a": "b"}}}}', '"values" member'];
        yield 'values holds an object (deeper than a claims request)' => ['{"id_token": {"acr": {"values": [{"a": "b"}]}}}', 'not valid JSON'];
        yield 'values holds null' => ['{"id_token": {"acr": {"values": [null]}}}', '"values" member'];
    }
}
