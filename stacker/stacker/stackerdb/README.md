# StackerDB (Postgres + pg_cron)

This image extends `postgres:16.13` with the `pg_cron` extension.

## Build

```
docker build -t stackerdb-pgcron:16.13 .
```

## Run (example)

```
docker run --name stackerdb \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  stackerdb-pgcron:16.13 \
  -c shared_preload_libraries=pg_cron \
  -c cron.database_name=stacker
```

## Enable extension

```
CREATE EXTENSION IF NOT EXISTS pg_cron;
```

## Verify job

```
SELECT * FROM cron.job WHERE jobname = 'stacker_command_queue_cleanup';
```
