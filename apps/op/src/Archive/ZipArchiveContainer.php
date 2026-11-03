<?php

declare(strict_types=1);

namespace App\Archive;

use Beffroi\Core\Domain\Archive\ArchivePassword;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\ArchiveContainerInterface;
use function file_get_contents;
use function is_file;
use function sprintf;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;
use ZipArchive;

/**
 * The archive of a person wrapped in a zip whose single entry is encrypted with AES-256 (issue #483).
 *
 * **Why a zip, and what it costs.** A person who downloads this opens it with what their machine has, and
 * an AES entry of a zip is what the most machines open: 7-Zip, Keka, WinRAR, p7zip, and the archive
 * managers of the desktop environments. It is not what every machine opens: the file manager of Windows
 * and the Archive Utility of macOS read the old ZipCrypto and not this, so somebody on either of them
 * installs a tool. The exchange is deliberate, because the alternative is ZipCrypto, which is broken, and
 * decision 0006 has no option to do it wrong.
 *
 * **What the format fixes and no caller chooses.** The AES entry derives its key with PBKDF2-HMAC-SHA1
 * over 1000 iterations (the WinZip AE-2 specification): libzip writes that count and nothing here can
 * raise it. Two things follow and both are written down rather than hidden. The strength of the file is
 * the length of the passphrase, which is why ArchivePassword refuses a short one. And what wrapping costs
 * this provider is that same fixed derivation, which is a millisecond on any machine: a download somebody
 * repeats costs what reading and unsealing the row costs, and not what a derivation chosen for a password
 * would cost.
 *
 * **It cannot answer by handing out a plain zip.** An installation whose libzip was built without crypto
 * refuses this download rather than writing an entry nothing protects: a file a person believes is wrapped
 * and is not is worse than a refusal they can read.
 *
 * **It writes a temporary file, and that file holds ciphertext.** libzip writes to a stream it opened
 * itself, and nothing of PHP's binding asks it for a buffer, so there is a path on the disk for as long as
 * the request lasts. What is on it is the encrypted entry: the document is handed to libzip in memory and
 * the bytes that land are the ones a browser gets. It is unlinked whatever happens.
 *
 * **What a zip leaves readable** is the name of the entry, its sizes and the moment it was written. The
 * name is the name of the archive, which names no person; the size says how much this provider holds of
 * somebody, and the moment says when they took it, which the journal says too. A container that hid all
 * three would be a container nothing lists.
 */
final readonly class ZipArchiveContainer implements ArchiveContainerInterface
{
    public const string MEDIA_TYPE = 'application/zip';

    public const string EXTENSION = 'zip';

    public function mediaType(): string
    {
        return self::MEDIA_TYPE;
    }

    public function extension(): string
    {
        return self::EXTENSION;
    }

    public function wrap(string $document, string $name, ArchivePassword $password): string
    {
        $path = tempnam(sys_get_temp_dir(), 'beffroi-archive-');
        if ($path === false) {
            throw new RuntimeException('No temporary file could be opened to write the archive into.');
        }

        try {
            return $this->write($path, $document, $name, $password);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    /**
     * @throws RuntimeException if libzip refuses any step, each of which is this installation and not this
     *                          request: the entry is encrypted or there is no file
     */
    private function write(string $path, string $document, string $name, ArchivePassword $password): string
    {
        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException(sprintf('No zip could be opened for writing (%s).', $zip->getStatusString()));
        }
        $zip->setPassword($password->value);
        if (! $zip->addFromString($name, $document)) {
            throw new RuntimeException(sprintf('The archive could not be written into the zip (%s).', $zip->getStatusString()));
        }
        // before close(), which is where libzip encrypts: a failure here is an installation whose libzip
        // was built without crypto, and the answer is a refusal and never an entry in the clear
        if (! $zip->setEncryptionName($name, ZipArchive::EM_AES_256)) {
            throw new RuntimeException(sprintf('This installation cannot write an AES-256 entry (%s).', $zip->getStatusString()));
        }
        if (! $zip->close()) {
            throw new RuntimeException(sprintf('The zip could not be closed (%s).', $zip->getStatusString()));
        }
        $wrapped = file_get_contents($path);
        if ($wrapped === false || $wrapped === '') {
            throw new RuntimeException('The zip was written and holds nothing.');
        }

        return $wrapped;
    }
}
