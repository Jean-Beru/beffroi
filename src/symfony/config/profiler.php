<?php

declare(strict_types=1);

use Heidi\Bundle\Http\AuthorizationRequestReaderInterface;
use Heidi\Bundle\Http\AuthorizationResponderInterface;
use Heidi\Bundle\Profiler\KmsClient;
use Heidi\Bundle\Profiler\OpCollector;
use Heidi\Bundle\Profiler\OpEndpointListener;
use Heidi\Bundle\Profiler\OpProfile;
use Heidi\Bundle\Profiler\OpResponseListener;
use Heidi\Bundle\Profiler\PanelValues;
use Heidi\Bundle\Profiler\ProfilingAccessTokenIssuer;
use Heidi\Bundle\Profiler\ProfilingAuthenticationSessionRepository;
use Heidi\Bundle\Profiler\ProfilingAuthorizationRequestReader;
use Heidi\Bundle\Profiler\Decision\ConsentRequiredObservation;
use Heidi\Bundle\Profiler\Decision\DecisionObservations;
use Heidi\Bundle\Profiler\Decision\GrantedObservation;
use Heidi\Bundle\Profiler\Decision\LoginRequiredObservation;
use Heidi\Bundle\Profiler\ProfilingAuthorizationResponder;
use Heidi\Bundle\Profiler\ProfilingClientRepository;
use Heidi\Bundle\Profiler\ProfilingCompactJwtReader;
use Heidi\Bundle\Profiler\ProfilingConsentRepository;
use Heidi\Bundle\Profiler\ProfilingDecryptionKeyProvider;
use Heidi\Bundle\Profiler\ProfilingEventDispatcher;
use Heidi\Bundle\Profiler\ProfilingIdTokenIssuer;
use Heidi\Bundle\Profiler\ProfilingInteractionRepository;
use Heidi\Bundle\Profiler\ProfilingSigningKeyProvider;
use Heidi\Bundle\Profiler\ProviderCapabilitiesListener;
use Heidi\Bundle\Messenger\EventBusDispatcher;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\DecryptionKeyProviderInterface;
use Heidi\Core\Port\SigningKeyProviderInterface;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/**
 * The panel of the provider in the profiler and in the debug toolbar (issue #152), wired only when the
 * kernel runs in debug: the application declares nothing, the panel is there because the bundle is.
 *
 * Every observer decorates a service that was already wired and adds nothing to what it does. Which
 * client, which key, which session, which token: each of them is read where the provider itself reads
 * it, so the panel says what the request did and never what a list kept beside it claims.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();
    $services->defaults()->autowire()->autoconfigure()->private();

    $services->set(OpProfile::class)->tag('kernel.reset', [
        'method' => 'reset',
    ]);
    $services->set(OpCollector::class)->tag('data_collector', [
        'id' => OpCollector::NAME,
        'template' => '@Heidi/profiler/panel.html.twig',
        'priority' => 300,
    ]);
    $services->set(PanelValues::class);
    $services->set(OpEndpointListener::class);
    // what the endpoint answered, member by member, no credential among them
    $services->set(OpResponseListener::class);
    // what this provider serves, read from the handler that answers the discovery endpoint
    $services->set(ProviderCapabilitiesListener::class);

    // what the request brought, and what the endpoint made of it
    $services
        ->set(ProfilingAuthorizationRequestReader::class)
        ->decorate(AuthorizationRequestReaderInterface::class)
        ->args([service('.inner')]);
    // what the panel says about a decision, one class per decision, as the renderers of the decisions are
    $services->set(LoginRequiredObservation::class)->tag('heidi.profiler.authorization_decision');
    $services->set(ConsentRequiredObservation::class)->tag('heidi.profiler.authorization_decision');
    $services->set(GrantedObservation::class)->tag('heidi.profiler.authorization_decision');
    $services->set(DecisionObservations::class)->args([tagged_iterator('heidi.profiler.authorization_decision')]);
    $services
        ->set(ProfilingAuthorizationResponder::class)
        ->decorate(AuthorizationResponderInterface::class)
        ->args([service('.inner')]);
    // every JWT a third party sent: the request object, the client assertion, the proof of possession
    $services
        ->set(ProfilingCompactJwtReader::class)
        ->decorate(CompactJwtReaderInterface::class)
        ->args([service('.inner')]);
    $services
        ->set(ProfilingInteractionRepository::class)
        ->decorate(InteractionRepositoryInterface::class)
        ->args([service('.inner')]);
    $services
        ->set(ProfilingClientRepository::class)
        ->decorate(ClientRepositoryInterface::class)
        ->args([service('.inner')]);
    $services
        ->set(ProfilingConsentRepository::class)
        ->decorate(ConsentRepositoryInterface::class)
        ->args([service('.inner')]);
    $services
        ->set(ProfilingAuthenticationSessionRepository::class)
        ->decorate(AuthenticationSessionRepositoryInterface::class)
        ->args([service('.inner')]);

    // what left, and what opened the keys that wrote it
    $services
        ->set(ProfilingAccessTokenIssuer::class)
        ->decorate(AccessTokenIssuerInterface::class)
        ->args([service('.inner')]);
    $services
        ->set(ProfilingIdTokenIssuer::class)
        ->decorate(IdTokenIssuerInterface::class)
        ->args([service('.inner')]);
    $services
        ->set(ProfilingSigningKeyProvider::class)
        ->decorate(SigningKeyProviderInterface::class)
        ->args([service('.inner')]);
    $services
        ->set(ProfilingDecryptionKeyProvider::class)
        ->decorate(DecryptionKeyProviderInterface::class)
        ->args([service('.inner')]);

    // the events the core announced on their way to the bus
    $services
        ->set(ProfilingEventDispatcher::class)
        ->decorate(EventBusDispatcher::class)
        ->args([service('.inner')]);

    // the KMS is named by the scheme of its DSN, which the extension hands over; the rest of a DSN may
    // carry a credential and never reaches the panel
    $services->set(KmsClient::class);
};
