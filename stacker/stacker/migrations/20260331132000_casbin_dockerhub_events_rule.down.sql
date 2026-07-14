DELETE FROM public.casbin_rule
WHERE ptype = 'p' AND v1 = '/dockerhub/events' AND v2 = 'POST';
