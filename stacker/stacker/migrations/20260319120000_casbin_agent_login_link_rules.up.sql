-- Allow anonymous (unauthenticated) access to POST /api/v1/agent/login
-- Status Panel agents call this endpoint to authenticate users against TryDirect OAuth.
-- The agent has no credentials yet at this point - user identity is the trust anchor.
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_anonymous', '/api/v1/agent/login', 'POST', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;

-- Allow anonymous access to POST /api/v1/agent/link
-- Status Panel agents call this after login to link to a specific deployment.
-- The session_token in the request body serves as authentication (validated server-side).
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_anonymous', '/api/v1/agent/link', 'POST', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
