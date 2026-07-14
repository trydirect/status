DELETE FROM public.casbin_rule WHERE v1 IN (
    '/api/admin/templates/:id/verifications',
    '/stacker/admin/templates/:id/verifications'
) AND v2 = 'PATCH';
