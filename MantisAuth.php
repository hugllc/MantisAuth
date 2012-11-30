<?php
/**
 * MediaWiki plugin to authenticate from a mantis database.
 *
 * PHP Version 5
 *
 * <pre>
 * Copyright (C) 2004 Brion Vibber <brion@pobox.com>
 * http://www.mediawiki.org/
 * Copyright (C) 2007-2009 Hunt Utilities Group, LLC
 * http://dev.hugllc.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 * </pre>
 *
 * This program has been modified from the original by Scott Price
 * on 2007-10-06.  The original File was includes/AuthPlugin.php in the
 * Mediawiki 1.10.0 distribution.  Documentation for AuthPlugin can be found
 * at {@link http://svn.wikimedia.org/doc/classAuthPlugin.html AuthPlugin}
 *
 * @category   Misc
 * @package    MantisAuth
 * @subpackage MantisAuth
 * @author     Scott Price <prices@hugllc.com>
 * @copyright  2007-2009 Hunt Utilities Group, LLC
 * @license    http://opensource.org/licenses/gpl-license.php GNU Public License
 * @version    Release: 0.0.5
 * @link       https://dev.hugllc.com/index.php/MantisAuth:Main_Page
 */
/** The version of MantisAuth */
define('MANTIS_AUTH_PLUGIN_VERSION', '0.0.5');

/** Information about the plugin */
$wgExtensionCredits['parserhook'][] = array (
    'name' => 'MantisAuth',
    'author' => 'Scott Price (prices@hugllc.com)',
    'url' => 'http://dev.hugllc.com/wiki/index.php/MantisAuth:Main_Page',
    'version' => MANTIS_AUTH_PLUGIN_VERSION,
    'description' => "Helps to integrate MediaWiki with Mantis Bug tracker "
                    ." (http://www.mantisbt.org) by authenticating MediaWiki "
                    ." users against the Mantis user table."
);

/** This is the auth plugin */
require_once 'includes/AuthPlugin.php';

// Get the session data
$wgHooks['UserLoadFromSession'][] = 'mantisAuthSession';

$g_bypass_headers = true;
$mantisAuthIncludeOkay = include_once $wgMantisPath.'/core.php';

/**
 * This plugin uses the Mantis database to authenticate people into MediaWiki.
 * It will automatically log users into both MediaWiki and Mantis if the user
 * logs into either one.  It will also logout similarly.  The user can also
 * create a new account from either and the rest is taken care of.
 *
 * The logout feature is in the extension hook.  I don't like this, but there
 * doesn't seem to be a way around it.
 *
 * New configuration options:
 * $wgMantisPath - The absolute path of the mantis installation
 * $wgMantisAuthOnly - Boolean - Return true if only Mantis Auth should be used
 * $wgMantisAutoCreateUser - Boolean - Return true if users in the MediaWiki
 *    db should be automatically created.
 *
 * Documentation for AuthPlugin can be found at
 * {@link http://svn.wikimedia.org/doc/classAuthPlugin.html AuthPlugin}
 *
 * If login succeeds, but a message comes up saying cookies are disabled and
 * required, set '$wgDisableCookieCheck = true;' in LocalSettings.php or see the
 * MediaWiki FAQ here:
 * http://meta.wikimedia.org/wiki/MediaWiki_FAQ#I_can_login_but_I_get_a_message_about_disabled_cookies_.28and_they.27re_not.21.29
 *
 * @category   Misc
 * @package    MantisAuth
 * @subpackage MantisAuth
 * @author     Scott Price <prices@hugllc.com>
 * @copyright  2007-2009 Hunt Utilities Group, LLC
 * @license    http://opensource.org/licenses/gpl-license.php GNU Public License
 * @link       https://dev.hugllc.com/index.php/MantisAuth:Main_Page
 */
class MantisAuthPlugin extends AuthPlugin
{
    /**
     * Register a function to be called on every page load
     * this allows us to automatically log in a user that
     * already has a valid Mantis session
     */
    function __construct()
    {
        global $mantisAuthIncludeOkay;
        global $wgMantisPath;
        if ($mantisAuthIncludeOkay != 1) {
            if (!isset($wgMantisPath)) {
                print 'Config variable $wgMantisPath must be set.<br /><br />';
                print 'Please set it in LocalSettings.php';
            } else {
                print 'Mantis installation not found.  ';
                print 'Please make sure $wgMantisPath is set properly.';
            }
            die();
        }

    }
    /**
     * Check whether there exists a user account with the given name.
     * The name will be normalized to MediaWiki's requirements, so
     * you might need to munge it (for instance, for lowercase initial
     * letters).
     *
     * @param string $username username.
     *
     * @return bool
     * @public
     */
    function userExists($username)
    {
        return (bool) user_get_id_by_name($username);
    }

    /**
     * Check if a username+password pair is a valid login.
     * The name will be normalized to MediaWiki's requirements, so
     * you might need to munge it (for instance, for lowercase initial
     * letters).
     *
     * @param string $username username.
     * @param string $password user password.
     *
     * @return bool
     * @public
     */
    function authenticate($username, $password)
    {
        return auth_attempt_login($username, $password);
    }

    /**
     * Modify options in the login template.
     *
     * @param object &$template UserLoginTemplate object.
     *
     * @return void
     * @public
     */
    function modifyUITemplate(&$template)
    {
        // Override this!
        $template->set('usedomain', false);
    }

    /**
     * Set the domain this plugin is supposed to use when authenticating.
     *
     * @param string $domain authentication domain.
     *
     * @return void
     * @public
     */
    function setDomain($domain)
    {
        $this->domain = $domain;
    }

    /**
     * Check to see if the specific domain is a valid domain.
     *
     * @param string $domain authentication domain.
     *
     * @return bool
     * @public
     */
    function validDomain($domain)
    {
        // Override this!
        return true;
    }

    /**
     * When a user logs in, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * @param object &$user User object
     *
     * @return bool
     * @public
     */
    function updateUser(&$user)
    {
        $id = user_get_id_by_name($user->mName);
        $user->setRealName(user_get_realname($id));
        $user->setEmail(user_get_email($id));
        $user->mEmailAuthenticated = wfTimestampNow();
        $user->saveSettings();
        return true;
    }


    /**
     * Return true if the wiki should create a new local account automatically
     * when asked to login a user who doesn't exist locally but does in the
     * external auth database.
     *
     * If you don't automatically create accounts, you must still create
     * accounts in some way. It's not possible to authenticate without
     * a local account.
     *
     * This is just a question, and shouldn't perform any actions.
     *
     * @return bool
     * @public
     */
    function autoCreate()
    {
        global $wgMantisAutoCreateUser;
        if (!is_bool($wgMantisAutoCreateUser)) {
            return true;
        }
        return $wgMantisAutoCreateUser;
    }

    /**
     * Can users change their passwords?
     *
     * @return bool
     */
    function allowPasswordChange()
    {
        return true;
    }

    /**
     * Set the given password in the authentication database.
     * As a special case, the password may be set to null to request
     * locking the password to an unusable value, with the expectation
     * that it will be set later through a mail reset or other method.
     *
     * Return true if successful.
     *
     * @param object $user     User object.
     * @param string $password password.
     *
     * @return bool
     * @public
     */
    function setPassword($user, $password)
    {
        if (empty($password)) {
            return true;
        }
        $id = user_get_id_by_name($user);
        // user_set_password( $p_user_id, $p_password, $p_allow_protected=false )
        return user_set_password($id, $password);
    }

    /**
     * Update user information in the external authentication database.
     * Return true if successful.
     *
     * @param object $user User object.
     *
     * @return bool
     *
     * @public
     */
    function updateExternalDB(&$user)
    {
        $id = user_get_id_by_name($user->mName);
        $user->setRealName(user_get_realname($id));
        $user->setEmail(user_get_email($id));
        $user->mEmailAuthenticated = wfTimestampNow();
        $user->saveSettings();
        return true;
    }

    /**
     * Check to see if external accounts can be created.
     * Return true if external accounts can be created.
     *
     * @return bool
     *
     * @public
     */
    function canCreateAccounts()
    {
        return true;
    }

    /**
     * Add a user to the external authentication database.
     * Return true if successful.
     *
     * @param object $user     only the name should be assumed valid at this point
     * @param string $password password
     * @param string $email    email address
     * @param string $realname user's real name
     *
     * @return bool
     * @public
     */
    function addUser( $user, $password, $email='', $realname='' )
    {
        //user_create( $p_username, $p_password, $p_email='', $p_access_level=null,
        // $p_protected=false, $p_enabled=true, $p_realname='' )
        return user_create(
            $user->mName,
            $password,
            $email,
            null,
            false,
            true,
            $realname
        );
    }


    /**
     * Return true to prevent logins that don't authenticate here from being
     * checked against the local database's password fields.
     *
     * This is just a question, and shouldn't perform any actions.
     *
     * @return bool
     * @public
     */
    function strict()
    {
        global $wgMantisAuthOnly;
        if (!is_bool($wgMantisAuthOnly)) {
            return false;
        }
        return (bool) $wgMantisAuthOnly;
    }

    /**
     * When creating a user account, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * @param object &$user User object.
     *
     * @return void
     * @public
     */
    function initUser(&$user)
    {
        $id = user_get_id_by_name($user->mName);
        $user->setRealName(user_get_realname($id));
        $user->setEmail(user_get_email($id));
        $user->mEmailAuthenticated = wfTimestampNow();
        $user->saveSettings();
    }

    /**
     * If you want to munge the case of an account name before the final
     * check, now is your chance.
     *
     * @param string $username The username
     *
     * @return string
     */
    function getCanonicalName($username)
    {
        return $username;
    }
}
/**
 * Auto login and logout are handled here.  It will also automatically
 * create a user if one doesn't exist.
 *
 * @param object $wgUser  The user object from MediaWiki
 * @param mixed  &$result The result of what happened
 *
 * This function does a number of functions.
 *  - It checks to see if a user is logged into Mantis.  If they are then
 *      they are also logged into MediaWiki.
 *  - It will automatically create users in MediaWiki if they only exist in Mantis.
 *  - It will log someone out of MediaWiki if they are not currently logged into
 *       Mantis.
 *
 * @return void
 */
function mantisAuthSession($wgUser, &$result)
{
    global $wgAuth;
    global $wgRequest;

    // If this is the logout page logout of Mantis.
    $title = $wgRequest->getVal('title');
    if (strtolower($title) == 'special:userlogout') {
        // Log out of Mantis
        auth_logout();
        return true;
    }


    // Check for an authenticated Mantis user
    if (auth_is_user_authenticated()) {
        $id = auth_get_current_user_id();
        // Return if there is already a valid session
        if ($wgUser->isLoggedIn()) {
            // Make sure the session is for the right user
            if (user_get_id_by_name($wgUser->getName()) == $id) {
                return true;
            } else {
                // Woah!  Different users are logged into Mantis and MediaWiki
                // Log the user out of MediaWiki.
                $wgUser->logout();
            }
        }

        // Get the Mantis user information
        $uInfo = user_cache_row($id, false);

        // check for anonymous login
        if (config_get('allow_anonymous_login')
            && (config_get('anonymous_account') == $uInfo["username"])
        ) {
            return true;
        }

        // Create a new user object
        $u = User::newFromName($uInfo["username"]);

        // Problem.  We don't have a valid user object.  Exit
        if (is_null($u)) {
            return true;
        }
        $wgUser = &$u;
        // Log the user in if it exists
        if ($u->getId() != 0) {
            $wgUser->setCookies();
            $wgUser->saveSettings();

            return true;
        }

        // Create user if it does not exist
        $wgUser->addToDatabase();
        $wgAuth->initUser($wgUser);
        $wgUser->saveSettings();

    } else {
         // If no user is logged into Mantis, logout any user logged into Mediawiki
        if ($wgUser->isLoggedIn()) {
            $wgUser->logout();
        }
    }
    return true;
}
?>
