# laravel-stack

`laravel-stack` is a Go gRPC specialist service that performs safe, read-only Laravel follow-up verification checks selected by the orchestrator.

## Included checks

- public `/.env` exposure
- exposed `/storage/logs/laravel.log`
- exposed `/vendor/composer/installed.json`
- Laravel Debugbar exposure via `/_debugbar/open`
- Ignition exposure via `/_ignition/health-check` and `/_ignition/execute-solution` (GET/HEAD only)
- debug/error disclosure markers on safe GET probes

All checks are non-destructive and use safe GET/HEAD requests with bounded response reads.
