<?php

declare(strict_types=1);

namespace App\DependencyInjection;

use function is_a;
use App\Doctrine\Type\NeedsAuthenticationPredicatesInterface;
use App\Doctrine\Type\NeedsAuthorizationDetailTypesInterface;
use App\Doctrine\Type\NeedsCodeChallengeMethodsInterface;
use App\Doctrine\Type\NeedsConfirmationReaderInterface;
use App\Doctrine\Type\NeedsPasswordAlgorithmsInterface;
use Beffroi\Core\Port\AuthenticationPredicatesInterface;
use Beffroi\Core\Port\PasswordAlgorithmsInterface;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use Beffroi\Oidc\Port\ConfirmationReaderInterface;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\KeyManagement\Bridge\DoctrineDbal\EncryptedTypes;

/**
 * What a kernel does for the provider: it registers the extension of the "beffroi:" tree and its passes
 * when the container is built, and it hands the Doctrine types their wiring when it boots. The kernel of
 * the application uses it, and so does the kernel of the suite of the integration (tests/symfony), so
 * that both boot the same provider.
 */
trait BeffroiKernelTrait
{
    protected function build(ContainerBuilder $container): void
    {
        $container->registerExtension(new BeffroiExtension());
        BeffroiExtension::addCompilerPasses($container);
    }

    /**
     * The types that read a wiring back are told what the deployment is wired with, as soon as the
     * container can answer: which algorithm a stored password hash names, which kind of confirmation a
     * stored "cnf" names, what an "authorization_details" a user agreed to asks for, which method a stored
     * PKCE challenge was made with, which predicate a stored "acr" policy and a stored login floor name. It
     * goes to the class and not to an instance: Doctrine builds its types itself, when a connection is
     * first made, so no instance of one exists while the kernel boots. A deployment has one wiring, and a
     * kernel booted after another hands over the same one.
     *
     * Only the boot that boots does it: a kernel served by a worker is asked to boot at every request and
     * returns at once from the second time on.
     */
    public function boot(): void
    {
        $booted = $this->booted;
        parent::boot();
        if ($booted || $this->container === null) {
            return;
        }
        $container = $this->container;
        $algorithms = $container->has('beffroi.password_algorithms') ? $container->get('beffroi.password_algorithms') : null;
        $confirmations = $container->has('beffroi.confirmations') ? $container->get('beffroi.confirmations') : null;
        $authorizationDetails = $container->has('beffroi.authorization_detail_types') ? $container->get('beffroi.authorization_detail_types') : null;
        $codeChallengeMethods = $container->has('beffroi.code_challenge_methods') ? $container->get('beffroi.code_challenge_methods') : null;
        $predicates = $container->has('beffroi.authentication_predicates') ? $container->get('beffroi.authentication_predicates') : null;
        foreach (BeffroiExtension::DBAL_TYPES as $class) {
            if ($algorithms instanceof PasswordAlgorithmsInterface && is_a($class, NeedsPasswordAlgorithmsInterface::class, true)) {
                $class::resolveWith($algorithms);
            }
            if ($confirmations instanceof ConfirmationReaderInterface && is_a($class, NeedsConfirmationReaderInterface::class, true)) {
                $class::resolveWith($confirmations);
            }
            if ($authorizationDetails instanceof AuthorizationDetailsReaderInterface && is_a($class, NeedsAuthorizationDetailTypesInterface::class, true)) {
                $class::resolveWith($authorizationDetails);
            }
            if ($codeChallengeMethods instanceof CodeChallengeMethodsInterface && is_a($class, NeedsCodeChallengeMethodsInterface::class, true)) {
                $class::resolveWith($codeChallengeMethods);
            }
            if ($predicates instanceof AuthenticationPredicatesInterface && is_a($class, NeedsAuthenticationPredicatesInterface::class, true)) {
                $class::resolveWith($predicates);
            }
        }
        $this->registerEncryptedTypes();
    }

    /**
     * The encrypted types of the columns that carry a personal datum (decisions 0011 and 0018,
     * EncryptedColumnTypes), declared as one service because each one holds an encrypter, which a class
     * DoctrineBundle instantiates with no argument cannot. Booting is where the bridge asks for it, and it
     * is early enough for every entry point at once: the front controller, the console with its schema
     * tool and its migrations, and the kernel of the suite. Registering twice is safe, which is what a
     * rebooted kernel does.
     *
     * A connection is asked for first, and this is the ordering nobody can see from the call: an encrypted
     * type resolves the type it decorates by name, in the global registry, at the moment it is registered,
     * and fourteen of them decorate a type of BeffroiExtension::DBAL_TYPES, which DoctrineBundle only puts
     * in that registry when a connection is first created (ConnectionFactory::initializeTypes). Asking
     * opens nothing, a DBAL connection reaching the database on its first query and not before.
     */
    private function registerEncryptedTypes(): void
    {
        $container = $this->container;
        if ($container === null || ! $container->has('beffroi.encrypted_types')) {
            return;
        }
        $doctrine = $container->has('doctrine') ? $container->get('doctrine') : null;
        if ($doctrine instanceof ManagerRegistry) {
            $doctrine->getConnection();
        }
        $types = $container->get('beffroi.encrypted_types');
        if ($types instanceof EncryptedTypes) {
            $types->register();
        }
    }
}
