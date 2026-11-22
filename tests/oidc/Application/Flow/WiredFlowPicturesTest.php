<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Flow;

use Beffroi\Oidc\Application\Flow\FlowShapeInterface;
use function array_map;
use Beffroi\Oidc\Application\Flow\TheClientActsForItself;
use Beffroi\Oidc\Application\Flow\TheClientAsksForATokenAlone;
use Beffroi\Oidc\Application\Flow\TheProviderIsAskedWhoTheUserIs;
use Beffroi\Oidc\Application\Flow\TheResourceServerAsksWhatTheTokenIs;
use Beffroi\Oidc\Application\Flow\TheRefreshTokenIsSpent;
use Beffroi\Oidc\Application\Flow\TheTokenIsGivenBack;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedOnAnotherDevice;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedThroughABackchannel;
use Beffroi\Oidc\Application\Flow\TheUserIsSentToTheClient;
use Beffroi\Oidc\Application\Token\GrantNames;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Beffroi\Oidc\Tests\Fixture\FakeBackchannelGrant;
use Beffroi\Oidc\Tests\Fixture\FakeFlowShape;
use Beffroi\Oidc\Tests\Fixture\FakeGrant;
use Beffroi\Oidc\Tests\Fixture\Flows;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class WiredFlowPicturesTest extends TestCase
{
    #[Test]
    public function thereIsOnePictureForEveryWiredGrant(): void
    {
        // Given
        $pictures = Flows::of(Grants::servedWithDeviceCode());

        // When
        $drawn = $pictures->pictures();

        // Then
        static::assertSame(
            ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
            array_map(static fn (FlowPicture $picture): string => $picture->grantType->value, $drawn),
        );
    }

    #[Test]
    public function aGrantThatIsNotWiredHasNoPicture(): void
    {
        // Given
        $pictures = Flows::of(Grants::served());

        // When
        $picture = $pictures->of(Grants::deviceCode());

        // Then
        static::assertNull($picture);
    }

    /**
     * RFC 8628 §3.3
     */
    #[Test]
    public function theOpeningOfAFlowIsTheCapabilityItsGrantDeclares(): void
    {
        // Given
        $pictures = Flows::of(Grants::servedWithDeviceCode());

        // When
        $picture = $pictures->of(Grants::deviceCode()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertSame(
            [
                'device_authorization_request',
                'device_authorization_response',
                'user_code',
                'token_request',
                'token_response',
                'userinfo_request',
                'userinfo_response',
                'introspection_request',
                'introspection_response',
                'revocation_request',
                'revocation_response',
            ],
            $picture->hopNames(),
        );
    }

    /**
     * CIBA Core §7
     */
    #[Test]
    public function aGrantWhoseUserIsReachedByTheProviderOpensOnTheBackchannel(): void
    {
        // Given
        $pictures = Flows::of(Grants::servedWithCiba());

        // When
        $picture = $pictures->of(Grants::ciba()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertSame(
            [
                'backchannel_authentication_request',
                'backchannel_authentication_response',
                'approval',
                'notification',
                'token_request',
                'token_response',
                'userinfo_request',
                'userinfo_response',
                'introspection_request',
                'introspection_response',
                'revocation_request',
                'revocation_response',
            ],
            $picture->hopNames(),
        );
    }

    /**
     * RFC 6749 §4.1
     */
    #[Test]
    public function aFlowThatSendsTheUserToTheClientIsDrawnBetweenTheFourActors(): void
    {
        // Given
        $pictures = Flows::of(Grants::served());

        // When
        $picture = $pictures->of(Grants::authorizationCode()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertSame([Actor::Browser, Actor::Client, Actor::Provider, Actor::ResourceServer], $picture->actors());
    }

    /**
     * RFC 6749 §4.1
     */
    #[Test]
    public function aFlowThatSendsTheUserToTheClientOpensInFourHops(): void
    {
        // Given
        $pictures = Flows::of(Grants::served(), null, []);

        // When
        $picture = $pictures->of(Grants::authorizationCode()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertSame(
            [
                'authorization_request',
                'authorization_response',
                'token_request',
                'token_response',
            ],
            $picture->hopNames(),
        );
    }

    /**
     * @return iterable<string, array{ServedGrantsInterface, GrantTypeName, list<string>}>
     */
    public static function provideFlowsAndTheirPolling(): iterable
    {
        yield 'a flow that sends the user to the client asks once' => [Grants::served(), Grants::authorizationCode(), []];
        yield 'a flow a client uses for itself asks once' => [Grants::servedWithClientCredentials(), Grants::clientCredentials(), []];
        yield 'a flow whose user is asked on another device polls' => [Grants::servedWithDeviceCode(), Grants::deviceCode(), ['token_request']];
        yield 'a flow whose user the provider reaches polls' => [Grants::servedWithCiba(), Grants::ciba(), ['token_request']];
    }

    /**
     * RFC 8628 §3.4, CIBA Core §10.1
     *
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideFlowsAndTheirPolling')]
    public function onlyAFlowWaitingOnSomebodyElseIsDrawnAsking(ServedGrantsInterface $served, GrantTypeName $grantType, array $expected): void
    {
        // Given
        $pictures = Flows::of($served);

        // When
        $picture = $pictures->of($grantType) ?? static::fail('A wired grant has a picture.');

        // Then
        $repeating = [];
        foreach ($picture->hops as $hop) {
            if ($hop->repeats) {
                $repeating[] = $hop->name;
            }
        }
        static::assertSame($expected, $repeating);
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function aFlowWithNobodyBehindItHasNoBrowserAndNoUserInfo(): void
    {
        // Given
        $pictures = Flows::of(Grants::servedWithClientCredentials());

        // When
        $picture = $pictures->of(Grants::clientCredentials()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertSame([Actor::Client, Actor::Provider, Actor::ResourceServer], $picture->actors());
        static::assertFalse($picture->draws('userinfo_request'));
    }

    /**
     * RFC 6749 §6
     */
    #[Test]
    public function onlyAFlowWhoseAnswerMayCarryARefreshTokenIsDrawnSpendingOne(): void
    {
        // Given
        $pictures = Flows::of(Grants::served());

        // When
        $issuing = $pictures->of(Grants::authorizationCode()) ?? static::fail('A wired grant has a picture.');
        $spending = $pictures->of(Grants::refreshToken()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertTrue($issuing->draws('refresh_request'));
        static::assertFalse($spending->draws('refresh_request'));
    }

    /**
     * RFC 6749 §4.5
     */
    #[Test]
    public function aGrantThatAsksNobodyAnythingOpensAtTheTokenEndpoint(): void
    {
        // Given
        $pictures = Flows::of(new ServedGrants([new FakeGrant(Grants::jwtBearer())]));

        // When
        $picture = $pictures->of(Grants::jwtBearer()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertSame(
            [
                'token_request',
                'token_response',
                'userinfo_request',
                'userinfo_response',
                'introspection_request',
                'introspection_response',
                'revocation_request',
                'revocation_response',
            ],
            $picture->hopNames(),
        );
    }

    #[Test]
    public function theClosingsComeInTheOrderTheyAreWired(): void
    {
        // Given
        $pictures = Flows::of(
            Grants::served(),
            [new FakeFlowShape([Grants::authorizationCode(), Grants::refreshToken()], 'opening')],
            [
                new FakeFlowShape([Grants::authorizationCode()], 'first'),
                new FakeFlowShape([Grants::authorizationCode()], 'second'),
            ],
        );

        // When
        $picture = $pictures->of(Grants::authorizationCode()) ?? static::fail('A wired grant has a picture.');

        // Then
        static::assertSame(['opening', 'first', 'second'], $picture->hopNames());
    }

    #[Test]
    public function aGrantTwoOpeningsClaimIsRefused(): void
    {
        // Given
        $pictures = Flows::of(
            Grants::served(),
            [
                new FakeFlowShape([Grants::authorizationCode()], 'sent_to_the_client'),
                new FakeFlowShape([Grants::authorizationCode()], 'asked_on_another_device'),
            ],
            [],
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The flow of "authorization_code" is opened by two shapes: a grant declares one way of reaching a token.');

        // When
        $pictures->pictures();
    }

    #[Test]
    public function aGrantNoOpeningDrawsIsRefused(): void
    {
        // Given
        $pictures = Flows::of(Grants::served(), [], []);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The flow of "authorization_code" is opened by no wired shape.');

        // When
        $pictures->pictures();
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function provideCapabilities(): iterable
    {
        yield 'the user is sent back to the client' => [TheUserIsSentToTheClient::class, ['authorization_code']];
        yield 'the user is asked on another device' => [TheUserIsAskedOnAnotherDevice::class, []];
        yield 'the user is reached by the provider' => [TheUserIsAskedThroughABackchannel::class, []];
        yield 'the client acts for itself' => [TheClientActsForItself::class, []];
        yield 'the client asks for a token alone' => [TheClientAsksForATokenAlone::class, ['refresh_token']];
        yield 'the provider is asked who the user is' => [TheProviderIsAskedWhoTheUserIs::class, ['authorization_code', 'refresh_token']];
        yield 'the resource server asks what the token is' => [TheResourceServerAsksWhatTheTokenIs::class, ['authorization_code', 'refresh_token']];
        yield 'the refresh token is spent' => [TheRefreshTokenIsSpent::class, ['authorization_code']];
        yield 'the token is given back' => [TheTokenIsGivenBack::class, ['authorization_code', 'refresh_token']];
    }

    /**
     * @param class-string<FlowShapeInterface> $shape
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideCapabilities')]
    public function eachShapeDrawsTheGrantsThatDeclareItsCapability(string $shape, array $expected): void
    {
        // Given
        $served = Grants::served();

        // When
        $grantTypes = new $shape()->grantTypes($served);

        // Then
        static::assertSame($expected, GrantNames::of($grantTypes));
    }

    /**
     * CIBA Core §7, RFC 8628 §3.3
     */
    #[Test]
    public function aWiringHoldsThePictureOfTheCapabilitiesItWiredAndNoOther(): void
    {
        // Given
        $pictures = Flows::of(new ServedGrants([new FakeBackchannelGrant(Grants::ciba())]));

        // When
        $drawn = $pictures->pictures();

        // Then
        static::assertCount(1, $drawn);
        static::assertTrue($drawn[0]->draws('backchannel_authentication_request'));
        static::assertFalse($drawn[0]->draws('device_authorization_request'));
    }
}
