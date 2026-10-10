<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\ArchivePage;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Core\Application\Archive\ArchiveHandout;
use Beffroi\Core\Domain\Archive\ArchivePassword;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\ArchiveContainerInterface;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The archive of a person handed to them wrapped in a container only their passphrase opens (issue #483).
 *
 * **It is a POST and not a GET, and the passphrase is in the body.** A passphrase in a query string is
 * written to every access log between here and the browser, kept in the history of that browser and sent
 * on in a referer: the one place a secret of a request belongs is the body of that request.
 *
 * **This is the one form of these pages that does not answer with a redirection** (issue #481), because
 * its answer is the file: there is nothing to redirect to that would still hold the passphrase, and a
 * passphrase kept across a redirection is a passphrase written to a session. The hazard that rule exists
 * for is not here either, an answer with `Content-Disposition: attachment` leaving the browser on the page
 * it posted from, so a reload reloads that page and posts nothing.
 *
 * **A passphrase that is refused takes nothing with it.** It is read and judged before the archive is
 * asked for, so a refusal is not an act: nothing left, and the journal does not say it did.
 *
 * Nothing to give is nothing, as on the plain download: a person who never asked, one whose file is still
 * being built and one whose file has expired all get a 404 and read which of the three it is on the page.
 */
#[AsController]
final readonly class AccountArchiveWrappedFileController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_archive_wrapped_file';

    public const string CSRF_TOKEN_ID = 'beffroi_archive_wrap';

    public const string PASSWORD_PARAMETER = 'password';

    public function __construct(
        private AccountAccess $account,
        private ArchiveHandout $handout,
        private ArchiveContainerInterface $container,
        private RequestContextFactory $contexts,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/archive/file', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $typed = RequestParameters::ofForm($request)[self::PASSWORD_PARAMETER] ?? null;
        try {
            $password = new ArchivePassword(is_string($typed) ? $typed : '');
        } catch (InvalidArgumentException) {
            // what the page says is that it was refused, and never what was typed nor how far off it was
            $this->refusals->keep($request, ArchivePage::PASSPHRASE_REFUSED);

            return $this->pages->afterTheForm(AccountArchiveController::ROUTE);
        }
        $archive = $this->handout->givenTo($session->user, $this->contexts->fromRequest($request));
        if ($archive === null || $archive->content === null) {
            throw new NotFoundHttpException('No archive is ready for this person.');
        }

        return $this->pages->download(
            $this->container->wrap($archive->content, $archive->fileName(), $password),
            $this->container->mediaType(),
            $archive->fileName($this->container->extension()),
        );
    }
}
