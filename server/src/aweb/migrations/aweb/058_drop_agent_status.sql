-- 058_drop_agent_status.sql
-- Drop the stored signed agent status reports and the status-host
-- designations. No other table references them.

DROP TABLE IF EXISTS {{tables.agent_status}};
DROP TABLE IF EXISTS {{tables.agent_status_hosts}};
