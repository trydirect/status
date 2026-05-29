DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v1 = '/api/templates/:id/resubmit' AND v2 = 'POST';
DELETE FROM public.casbin_rule WHERE ptype = 'p' AND v1 = '/stacker/templates/:id/resubmit' AND v2 = 'POST';
