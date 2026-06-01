-- Fix: Allow anonymous (unauthenticated) access to POST /api/v1/agent/register
-- Ansible-triggered deployments call this endpoint without an Authorization header.
-- The anonym subject is mapped to group_anonymous via the initial seed rules,
-- so granting group_anonymous access here covers all unauthenticated callers.
--
-- This is an idempotent re-insert of the rule from
-- 20251222160220_casbin_agent_rules.up.sql which may be missing in production.

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_anonymous', '/api/v1/agent/register', 'POST', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
