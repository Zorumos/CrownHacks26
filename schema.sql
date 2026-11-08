-- Run once with a migration/admin database role. The application role needs
-- SELECT, INSERT, UPDATE on this table; it does not need database-owner rights.
CREATE TABLE IF NOT EXISTS cyber_state (
  id integer PRIMARY KEY CHECK (id = 1),
  payload jsonb NOT NULL
);
-- Example after creating a dedicated cyber_app role separately:
-- GRANT SELECT, INSERT, UPDATE ON cyber_state TO cyber_app;
