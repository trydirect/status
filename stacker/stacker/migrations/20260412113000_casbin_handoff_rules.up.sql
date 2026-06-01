-- Allow authenticated users to mint CLI handoff commands for their deployments.
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/api/v1/handoff/mint', 'POST', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;

-- Allow anonymous resolution because the handoff token itself is the credential.
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_anonymous', '/api/v1/handoff/resolve', 'POST', '', '', '')
ON CONFLICT ON CONSTRAINT unique_key_sqlx_adapter DO NOTHING;
