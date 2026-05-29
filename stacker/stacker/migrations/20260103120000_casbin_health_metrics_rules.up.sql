-- Add Casbin rules for health check metrics endpoint
-- Allow all groups to access health check metrics for monitoring

-- Anonymous users can check health metrics
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_anonymous', '/health_check/metrics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

-- Regular users can check health metrics  
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_user', '/health_check/metrics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

-- Admins can check health metrics
INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5) 
VALUES ('p', 'group_admin', '/health_check/metrics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
