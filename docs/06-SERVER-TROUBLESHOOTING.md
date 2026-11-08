# Diagnose generic server errors safely

Admin login needs the hosted database and the encryption key in addition to ADMIN_SECRET. A generic 500 response does not establish that the admin password is wrong.

Deploy this update, retry once, and inspect Vercel → project → Logs for the failed `/api/index` request. The log now includes a bounded code, stage, optional PostgreSQL/network code and request reference. It never includes raw connection strings, passwords, SQL parameters or encrypted data. Public responses remain generic and include only a reference.

| Code | Meaning / next check |
|---|---|
| DB_NOT_CONFIGURED | DATABASE_URL is absent from the running deployment. Set it for Production and redeploy. |
| DB_URL_INVALID | DATABASE_URL must be a PostgreSQL URL copied without surrounding quotes or whitespace. |
| DB_DRIVER_FAILED | PostgreSQL driver could not load; verify package.json is deployed and dependencies installed. |
| DB_CONNECT_FAILED | Database connection failed; check connection string, host, credentials, network and database availability. Detail 28P01 means database authentication failed. |
| DB_TLS_FAILED | TLS/certificate negotiation failed. Keep certificate verification enabled; inspect the provider's supported connection-string settings. |
| DB_READ_FAILED, detail 42P01 | cyber_state table is missing from the branch/database used by DATABASE_URL. Run schema.sql in that exact database. |
| DB_READ_FAILED or DB_WRITE_FAILED, detail 42501 | The runtime database role lacks permissions. Use the schema owner to grant only the required schema/table access. |
| STATE_DECRYPT_FAILED | Existing data failed authenticated decryption. Restore the exact original ENCRYPTION_KEY for this database; corruption is another possibility. Do not generate a new key or delete records as a first troubleshooting step. |
| DB_TRANSACTION_FAILED / DB_WRITE_FAILED | Inspect the bounded detail code and database health/permissions. |
| INTERNAL_ERROR | The failure is outside the classified storage paths; share only the safe code/reference with the developer. |

Run this read-only query in the provider SQL editor to check table access without revealing account contents:

```sql
SELECT id FROM public.cyber_state;
```

An empty result means the table exists but contains no application state. A row with id=1 contains encrypted application state, not a single user's account. Do not delete that row: it holds the application data for every household.

Use the same database branch and role as the connection string when checking permissions. The application role requires schema usage plus SELECT, INSERT and UPDATE on cyber_state. Apply permission changes using the table owner and the actual runtime role name; do not grant public/global access.

Production and Preview may use separate databases. If they share the same database, the ENCRYPTION_KEY and CODE_PEPPER values must be consistent for that database. Changing an environment scope alone does not update an already-running deployment: redeploy afterward.

The update improves diagnosis; it cannot repair remote credentials, missing provider tables, or a lost original encryption key automatically. Live PostgreSQL remains unverified in the build environment.
