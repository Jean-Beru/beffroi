<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Archive\ArchiveHandout;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The archive handed to the person who asked for it (issue #453), and to nobody else.
 *
 * **The route carries no identifier.** What it serves is the archive of whoever is signed in, so there is
 * nothing to guess, nothing to compare and no way to write the comparison wrongly: "it is served to that
 * person and to nobody else" is a property of the route and not a check somebody remembered.
 *
 * Nothing to give is nothing: a person who never asked, one whose file is still being built and one whose
 * file has expired all get a 404 here, and read which of the three it is on the page of the archive.
 */
#[AsController]
final readonly class AccountArchiveFileController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_archive_file';

    public function __construct(
        private AccountAccess $account,
        private ArchiveHandout $handout,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/archive/file', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }
        $archive = $this->handout->givenTo($session->user, $this->contexts->fromRequest($request));
        if ($archive === null || $archive->content === null) {
            throw new NotFoundHttpException('No archive is ready for this person.');
        }

        return $this->pages->download($archive->content, PersonalArchive::MEDIA_TYPE, $archive->fileName());
    }
}
