DELETE FROM public.casbin_rule WHERE v1 IN (
    '/api/admin/templates/:id/vendor-profile',
    '/stacker/api/admin/templates/:id/vendor-profile'
) AND v2 = 'PATCH';
