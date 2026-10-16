certbot-dns-godaddy-v3
======================

[![Version](https://img.shields.io/pypi/v/certbot-dns-godaddy-v3.svg)](https://pypi.org/project/certbot-dns-godaddy-v3/) [![License: Apache](https://img.shields.io/pypi/l/certbot-dns-godaddy-v3.svg)](https://github.com/Responsible-User/certbot-dns-godaddy-v3/blob/main/LICENSE.txt)

[godaddy](https://www.godaddy.com/) DNS Authenticator plugin for [certbot](https://certbot.eff.org/).

**This is a fork of [miigotu/certbot-dns-godaddy](https://github.com/miigotu/certbot-dns-godaddy)** by Dustyn Gibson, rewritten to use GoDaddy's Domains v3 API with Personal Access Tokens and to support current certbot releases. It is tested and working as of October 2026. It is published on PyPI as `certbot-dns-godaddy-v3` and registers the certbot plugin `dns-godaddy-v3`, so it can be installed alongside the original package.

This plugin automates the process of completing a `dns-01` challenge by creating, and subsequently removing, `TXT` records using the GoDaddy [Domains v3 API](https://developer.godaddy.com/docs/api-users/domains/manage/dns), authenticated with a [Personal Access Token](https://developer.godaddy.com/docs/api-users/auth/how-to).

**Requirements:** Python >= 3.10 and certbot >= 2.8.0 (tested through certbot 5.8).

**Coming from the original plugin?** See [Switching from certbot-dns-godaddy](#switching-from-certbot-dns-godaddy).

Installation
------------

    # create a virtual environment, to avoid conflicts
    python3 -m venv /some/path

    # use the pip in the virtual environment to install or update
    /some/path/bin/pip install -U certbot-dns-godaddy-v3

    # use the certbot from the virtualenv, to avoid accidentally
    # using one from a different environment that does not have this library
    /some/path/bin/certbot

Named Arguments
---------------

To start using DNS authentication for godaddy, pass the following arguments on certbot's command line:

| Option                                     | Description                                                                          |
|--------------------------------------------|--------------------------------------------------------------------------------------|
| `--authenticator dns-godaddy-v3`           | select the authenticator plugin (Required)                                           |
| `--dns-godaddy-v3-credentials FILE`        | godaddy credentials INI file. (Required)                                             |
| `--dns-godaddy-v3-propagation-seconds NUM` | how long to wait before ACME tries to verify DNS. (Default: 30, Recommended: 60-120) |
| `--dns-godaddy-v3-ttl NUM`                 | TTL of the TXT record in seconds. GoDaddy accepts 600 to 86400. (Default: 600)       |

GoDaddy's authoritative nameservers usually serve new records within a few seconds, so a propagation time of 60-120 seconds is recommended. Increase it if validation fails because the record wasn't found.

Credentials
-----------

Use of this plugin requires a configuration file containing a GoDaddy Personal Access Token (PAT). To create one:

1. Sign in on the [Personal Access Token](https://developer.godaddy.com/personal-access-token) page and select **Generate Token**.
2. Give it a name, choose how long it stays valid (7, 30, 60 or 90 days, or 1 year), and grant it these scopes (under **Domains & DNS**):
   * `domains.domain:read`, used to find the DNS zone and existing records
   * `domains.dns:update`, used to create and delete the TXT records
3. Select **Create Token** and copy it. GoDaddy only shows it once.

An example `credentials.ini` file:

``` {.sourceCode .ini}
dns_godaddy_v3_token = your-personal-access-token
```

**Token expiry:** a PAT stops working when it expires (after one year at most), and automatic renewals will then fail with an HTTP 401 error. Note the expiry date and replace the token in the credentials file before then.

The path to this file can be provided interactively or using the `--dns-godaddy-v3-credentials` command-line argument. Certbot records the path to this file for use during renewal, but does not store the file's contents.

**CAUTION:** You should protect these API credentials as you would the password to your godaddy account. Users who can read this file can use these credentials to issue arbitrary API calls on your behalf. Users who can cause Certbot to run using these credentials can complete a `dns-01` challenge to acquire new certificates or revoke existing certificates for associated domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be accessed by other users on your system. The warning reads "Unsafe permissions on credentials configuration file", followed by the path to the credentials file. This warning will be emitted each time Certbot uses the credentials file, including for renewal, and cannot be silenced except by addressing the issue (e.g., by using a command like `chmod 600` to restrict access to the file).

Examples
--------

To acquire a single certificate for both `example.com` and `*.example.com`, waiting 120 seconds for DNS propagation:

    certbot certonly \\
      --authenticator dns-godaddy-v3 \\
      --dns-godaddy-v3-credentials ~/.secrets/certbot/godaddy.ini \\
      --dns-godaddy-v3-propagation-seconds 120 \\
      --dns-godaddy-v3-ttl 600 \\
      --keep-until-expiring --non-interactive --expand \
      --server https://acme-v02.api.letsencrypt.org/directory \
      -d 'example.com' \\
      -d '*.example.com'

Docker
------

You can build a docker image from source using the included `Dockerfile`:

    docker build -t certbot-dns-godaddy-v3 .

Once that's finished, the application can be run as follows:

    docker run --rm \
      -v /var/lib/letsencrypt:/var/lib/letsencrypt \
      -v /etc/letsencrypt:/etc/letsencrypt \
      --cap-drop=all \
      certbot-dns-godaddy-v3 certbot certonly \
        --authenticator dns-godaddy-v3 \
        --dns-godaddy-v3-propagation-seconds 120 \
        --dns-godaddy-v3-ttl 600 \
        --dns-godaddy-v3-credentials /var/lib/letsencrypt/godaddy_credentials.ini \
        --keep-until-expiring --non-interactive --expand \
        --server https://acme-v02.api.letsencrypt.org/directory \
        --agree-tos --email "webmaster@example.com" \
        -d example.com -d '*.example.com'

You may want to change the volumes `/var/lib/letsencrypt` and `/etc/letsencrypt` to local directories where the certificates and configuration should be stored.

Switching from certbot-dns-godaddy
----------------------------------

The original `certbot-dns-godaddy` plugin no longer works, because it uses GoDaddy's classic API key/secret, which the Domains v3 API does not accept. This package is a separate plugin, so certificates set up with the original need to be switched over:

1. Install this package: `pip install certbot-dns-godaddy-v3`. You can then `pip uninstall certbot-dns-godaddy`.
2. Create a Personal Access Token as described in [Credentials](#credentials), and replace the `dns_godaddy_key` and `dns_godaddy_secret` lines in your credentials file with `dns_godaddy_v3_token = <token>`.
3. For each certificate, run `certbot certonly --cert-name <name> --force-renewal` with the same `-d` domains, `--authenticator dns-godaddy-v3` and the `--dns-godaddy-v3-*` options shown above (`certbot certificates` lists the names). Certbot then records the new plugin in that certificate's renewal configuration, and `certbot renew` keeps using it.

If the credentials file still contains a key and secret, certbot stops with an error explaining step 2.

Credits
-------

This project started as a fork of [certbot-dns-godaddy](https://github.com/miigotu/certbot-dns-godaddy) by Dustyn Gibson ([@miigotu](https://github.com/miigotu)), which is no longer maintained. Thanks to Dustyn and that project's contributors for the original plugin. The Domains v3 rewrite is maintained by [@Responsible-User](https://github.com/Responsible-User). Both are licensed under the [Apache License 2.0](LICENSE.txt).
