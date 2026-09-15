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
    /**
     * OIDC Core §5.5, the example of the specification: "userinfo" and "id_token" members, a claim that is
     * null, essential claims, a claim with a value and one with a set of values.
     */
    #[Test]
    public function itReadsTheExampleOfTheSpecification(): void
    {
        $claims = ClaimsRequest::fromJson('{
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
        }');

        static::assertSame(['given_name', 'nickname', 'email', 'email_verified', 'picture', 'http://example.info/claims/groups'], array_keys($claims->userinfo));
        static::assertEquals(new ClaimRequest(true), $claims->userinfo['given_name']);
        static::assertEquals(new ClaimRequest(), $claims->userinfo['nickname']);
        static::assertFalse($claims->userinfo['nickname']->essential);
        static::assertSame(['auth_time', 'acr'], array_keys($claims->idToken));
        static::assertEquals(new ClaimRequest(false, null, ['urn:mace:incommon:iap:silver']), $claims->idToken['acr']);
        static::assertFalse($claims->isEmpty());
    }

    /**
     * OIDC Core §5.5.1: "value" requests a particular value; it is a JSON scalar kept as sent, so a
     * boolean stays a boolean and a number stays a number.
     */
    #[Test]
    public function itKeepsTheRequestedValueAsSent(): void
    {
        $claims = ClaimsRequest::fromJson('{"id_token": {"sub": {"value": "248289761001"}, "email_verified": {"value": true}, "updated_at": {"values": [1, 2.5]}}}');

        static::assertSame('248289761001', $claims->idToken['sub']->value);
        static::assertTrue($claims->idToken['email_verified']->value);
        static::assertSame([1, 2.5], $claims->idToken['updated_at']->values);
    }

    /**
     * OIDC Core §5.5: members that are not understood are ignored; an empty object or an absent member
     * asks for nothing.
     */
    #[Test]
    public function itIgnoresWhatItDoesNotUnderstand(): void
    {
        $claims = ClaimsRequest::fromJson('{"userinfo": null, "other": {"deep": {"deeper": [1]}}, "id_token": {"sub": {"essential": false, "extra": "ignored"}}}');

        static::assertSame([], $claims->userinfo);
        static::assertEquals(new ClaimRequest(false), $claims->idToken['sub']);
        static::assertTrue(ClaimsRequest::fromJson('{}')->isEmpty());
        static::assertTrue(ClaimsRequest::fromJson('{"userinfo": {}, "id_token": {}}')->isEmpty());
        static::assertFalse(ClaimsRequest::fromJson('{"userinfo": {"email": null}}')->isEmpty());
        static::assertFalse(ClaimsRequest::fromJson('{"id_token": {"email": null}}')->isEmpty());
    }

    /**
     * OIDC Core §5.5 and §5.5.1: a member that is understood but malformed is refused, and "essential" is
     * a JSON boolean, never a string that looks like one.
     */
    #[Test]
    #[DataProvider('provideMalformedRequests')]
    public function itRefusesAMalformedRequest(string $json, string $reason): void
    {
        try {
            ClaimsRequest::fromJson($json);
            static::fail('The claims request should have been rejected.');
        } catch (InvalidArgumentException $exception) {
            static::assertStringContainsString($reason, $exception->getMessage());
        }
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
