# php-stack

`php-stack` is a Go gRPC specialist service that performs safe, read-only PHP follow-up verification checks selected by the orchestrator.

## Included checks

- exposed phpinfo endpoints (`/phpinfo.php`, `/info.php`, `/test.php`)
- exposed config files (`/config.php`, `/config.bak`, `/config.old`)
- exposed SQL dumps (`/database.sql`, `/db.sql`)
- exposed backup archives (`/backup.zip`, `/backup.tar.gz`) via bounded HEAD/GET probes
- exposed Apache `.htaccess`
- exposed `.user.ini`
- PHP version disclosure via response headers

All checks are non-destructive and use safe GET/HEAD requests with bounded response reads.
