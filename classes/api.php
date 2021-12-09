<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace auth_saml2;

defined('MOODLE_INTERNAL') || die();
use moodle_url;

/**
 * Static list of api methods for auth saml2 configuration.
 *
 * @package   auth_saml2
 * @author    Brendan Heywood <brendan@catalyst-au.net>
 * @copyright Catalyst IT
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class api {

    /**
     * IdP logout callback. Called only when logout is initiated from IdP.
     * {@see saml2-logout.php}
     */
    public static function logout_from_idp_front_channel(): void {
        // The SP session will be cleaned up. Log user out of Moodle.
        require_logout();
    }

    public static function logout_from_idp_back_channel($username, $sessionId): void {
        global $DB;
        if (isset($sessionId)) {
            $DB->delete_records('auth_saml2_kvstore', array('k' => $sessionId));
        }

        $userid = $DB->get_record('user', array('username' => $username), 'id');        
        $mdsessionids = $DB->get_records('sessions', array('userid' => $userid->id), 'sid DESC', 'sid');
        foreach ($mdsessionids as $mdsessionid) {
            $DB->delete_records('sessions', array('sid' => $mdsessionid->sid));
        }
    }

    /**
     * Reads the soap message and kills the moodle sessions associated with the nameId 
     * and the sessionIndexes
     * 
     * @throws \Exception
     */
    public static function logout_from_idp_back_channel(): void
    {
        $script = $_SERVER['PHP_SELF'];
        // We only do something if we are coming from smal2-logout.php script
        if (strpos($script, '/saml2-logout.php') === false) {
            return;
        }
        $store = \SimpleSAML\Store::getInstance();
        try {
            $binding = \SAML2\Binding::getCurrentBinding();
        } catch (\Exception $e) {
            return;
        }
        if (get_class($binding) != 'SAML2\SOAP') { 
            return;
        }
        // If we get there we have a SOAP logout request
        $message = $binding->receive();
        if ($message->isNameIdEncrypted()) {

            // Get idpMetaData & spMetaData
            $sourceId = substr($_SERVER['PATH_INFO'], 1);
            /** @var \SimpleSAML\Module\saml\Auth\Source\SP $source */
            $source = \SimpleSAML\Auth\Source::getById($sourceId, '\SimpleSAML\Module\saml\Auth\Source\SP');
            $issuer = $message->getIssuer();
            $spMetadata = $source->getMetadata();
            $idpMetadata = $source->getIdPMetadata($issuer);

            try {
                $keys = \SimpleSAML\Module\saml\Message::getDecryptionKeys($idpMetadata, $spMetadata);
            } catch (\Exception $e) {
                throw new \SimpleSAML\Error\Exception('Error decrypting NameID: ' . $e->getMessage());
            }
                
            $blacklist = \SimpleSAML\Module\saml\Message::getBlacklistedAlgorithms($idpMetadata, $spMetadata);

            $lastException = null;
            foreach ($keys as $i => $key) {
                try {
                    $message->decryptNameId($key, $blacklist);
                    \SimpleSAML\Logger::debug('Decryption with key #' . $i . ' succeeded.');
                    $lastException = null;
                    break;
                } catch (\Exception $e) {
                    \SimpleSAML\Logger::debug('Decryption with key #' . $i . ' failed with exception: ' . $e->getMessage());
                    $lastException = $e;
                }
            }
            if ($lastException !== null) {
                throw $lastException;
            }
        }

        $nameId = $message->getNameId();
        if (is_array($nameId)) {
            /** @psalm-suppress UndefinedMethod */
            $nameId = \SAML2\XML\saml\NameID::fromArray($nameId);
        }
        $strNameId = serialize($nameId);
        $strNameId = sha1($strNameId);
        $sessionIndexes = $message->getSessionIndexes();
        // Normalize SessionIndexes

        // Kills moodle session
        foreach ($sessionIndexes as &$sessionIndex) {
            assert(is_string($sessionIndex));
            if (strlen($sessionIndex) > 50) {
                $sessionIndex = sha1($sessionIndex);

                $sessionId = $store->get('saml.LogoutStore', $strNameId . ':' . $sessionIndex);
                $session = \SimpleSAML\Session::getSession($sessionId);
                \core\session\manager::kill_session($session->moodle_session_id);
            }
        }
    }


    /**
     * SP logout callback. Called in case of normal Moodle logout.
     * {@see auth::logoutpage_hook}
     *
     * @param array $state Information about the current logout operation.
     */
    public static function after_logout_from_sp($state): void {
        global $saml2config;

        $cookiename = $saml2config['session.cookie.name'];
        $sessid = $_COOKIE[$cookiename];

        // In SSP should do this for us but remove stored SP session data.
        $storeclass = $saml2config['store.type'];
        $store = new $storeclass;
        $store->delete('session', $sessid);

        redirect(new moodle_url($state['ReturnTo']));
    }

    /**
     * Used to populate authproc.sp config attribute with a list of callbacks
     * defined in other components.
     *
     * @return array
     */
    public static function authproc_filters_hook(): array {
        $authprocfilters = [];
        $authprocfilters[50] = array(
            'class' => 'core:AttributeMap',
            'oid2name',
        );
        $callbacks = get_plugins_with_function('extend_auth_saml2_proc', 'lib.php');
        foreach ($callbacks as $plugins) {
            foreach ($plugins as $pluginfunction) {
                $filters = $pluginfunction();
                foreach ($filters as $key => $value) {
                    $key = self::check_filters_priority($key, $authprocfilters);
                    $authprocfilters[$key] = $value;
                }
            }
        }
        return $authprocfilters;
    }

    /**
     * Helper method to find unique key {@see self::saml2_authproc_filters_hook}.
     *
     * @param int $priority
     * @param array $filters
     * @return int
     */
    private static function check_filters_priority($priority, $filters): int {
        $uniquekey = false;
        while (!$uniquekey) {
            if (!array_key_exists($priority, $filters)) {
                $uniquekey = true;
            } else {
                $priority++;
            }
        }
        return $priority;
    }

    /**
     * Is the plugin enabled.
     *
     * @return bool
     */
    public static function is_enabled(): bool {
        return is_enabled_auth('saml2');
    }
}
