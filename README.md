MantisAuth
==========

This is a MediaWiki plugin so MediaWiki will authenticate to a Mantis user database.

### Requirements
Medawiki > 1.10.0

Not all versions have been tested.

### Setup

MantisAuth.php should go into the mediawiki/extensions/ directory.  Then the following needs
to be put into the LocalSettings.php file:

> $wgMantisPath = "/base/path/to/mantis";
> $wgMantisAuthOnly = TRUE;
> $wgMantisAutoCreateUser = TRUE;
> require_once('extensions/MantisAuth.php');
> $wgAuth = new MantisAuthPlugin();


## Contributing changes

Changes can be contributed by either:

1. Using git to create patches and emailing them to patches@hugllc.com
2. Creating another github repository to make your changes to and submitting pull requests.

## Filing Bug Reports
The bug tracker for this project is at http://dev.hugllc.com/bugs/ .  If you want an
account on that site, please email prices@hugllc.com.

## License
This is released under the GNU GPL V3.  You can find the complete text in the
LICENSE file, or at http://opensource.org/licenses/gpl-3.0.html
