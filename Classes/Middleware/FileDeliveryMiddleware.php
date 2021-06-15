<?php
declare(strict_types = 1);
namespace Bitmotion\SecureDownloads\Middleware;

/***
 *
 * This file is part of the "Secure Downloads" Extension for TYPO3 CMS.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 *  (c) 2019 Florian Wessels <f.wessels@Leuchtfeuer.com>, Leuchtfeuer Digital Marketing
 *
 ***/

use Bitmotion\SecureDownloads\Domain\Transfer\ExtensionConfiguration;
use Bitmotion\SecureDownloads\Resource\FileDelivery;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * PSR-15 middleware for delivering secured files to the browser.
 */
class FileDeliveryMiddleware implements MiddlewareInterface
{
    /**
     * @var string The URL schema before JWT
     */
    protected $assetPrefix;

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $extensionConfiguration = GeneralUtility::makeInstance(ExtensionConfiguration::class);
        $this->assetPrefix = sprintf(
          '%s%s/%s',
          $request->getAttributes()['normalizedParams']->getSitePath(),
          $extensionConfiguration->getLinkPrefix(),
          $extensionConfiguration->getTokenPrefix()
        );
        if ($this->isResponsible($request)) {

            // TODO: Remove the $GLOBALS array when dropping TYPO3 9 LTS support
            $frontendUserAuthentication = $request->getAttribute('frontend.user') ?? $GLOBALS['TSFE']->fe_user;
            $frontendUserAuthentication->fetchGroupData();

            ######################################################################################################################
            # Tel que constaté dans le fichier /public/typo3/sysext/frontend/Classes/Authentication/FrontendUserAuthentication.php
            # à la ligne 309, la fonction fetchGroupData() retourne seulement le nombre de fe_groups associé à l'utilisateur.
            # Secure_downloads ne semble pas faire grand chose avec le retour de fonction... La propriété publique $groupData
            # contient les informations des groupes.
            #
            # l'extensions secure_downloads offre une option enableGroupCheck qui est utilisé dans la classe FileDelivery.php
            # mais qui est dans une section du code qui est destiné à être éliminé pour la version 5.x de cet extension.
            # Il semble que la validation du groupe ne se fait pas en utilisant le token JWT.
            #
            # Dans la fonction FileDelivery()->getDataFromJsonWebToken($jwt) appelé dans le constructeur de cette dernière,
            # Des données sont décodés à partir du JWT et une série de groupes sont retournés dont entre autre le id:1 qui est __tout-udes
            # Il faudrait comprendre comment cette liste de groupe associé au fichier est généré car ça mismatch avec les groupes assigné
            # sur la page.


            # $frontendUserAuthentication->groupData
            $cleanPath = mb_substr(urldecode($request->getUri()->getPath()), mb_strlen($this->assetPrefix));
            [$jwt, $basePath] = explode('/', $cleanPath);
            return (new FileDelivery($jwt))->deliver($request);
        }

        return $handler->handle($request);
    }

    public function isResponsible(ServerRequestInterface $request)
    {
        return mb_strpos(urldecode($request->getUri()->getPath()), $this->assetPrefix) === 0 && $request->getMethod() === 'GET';
    }
}
