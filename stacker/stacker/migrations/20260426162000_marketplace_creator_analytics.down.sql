DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v1 = '/api/templates/mine/analytics'
  AND v2 = 'GET'
  AND v0 IN ('group_user', 'group_admin');

DROP TABLE IF EXISTS marketplace_template_event;
