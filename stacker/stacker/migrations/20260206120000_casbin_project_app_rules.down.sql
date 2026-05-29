-- Remove Casbin rules for project app routes
DELETE FROM public.casbin_rule
WHERE ptype = 'p'
  AND v0 = 'group_user'
  AND v1 IN (
    '/project/:id/apps',
    '/project/:id/apps/:code',
    '/project/:id/apps/:code/config',
    '/project/:id/apps/:code/env',
    '/project/:id/apps/:code/env/:name',
    '/project/:id/apps/:code/ports',
    '/project/:id/apps/:code/domain'
  );
