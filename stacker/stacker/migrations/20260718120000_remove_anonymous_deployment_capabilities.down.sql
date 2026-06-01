INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
SELECT 'p',
       'group_anonymous',
       '/api/v1/deployments/:deployment_hash/capabilities',
       'GET',
       NULL,
       NULL,
       NULL
WHERE NOT EXISTS (
    SELECT 1
    FROM public.casbin_rule
    WHERE ptype = 'p'
      AND v0 = 'group_anonymous'
      AND v1 = '/api/v1/deployments/:deployment_hash/capabilities'
      AND v2 = 'GET'
);
