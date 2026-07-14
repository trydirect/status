INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
SELECT 'g', 'creator', 'group_user', '', '', '', ''
WHERE NOT EXISTS (
    SELECT 1 FROM public.casbin_rule
    WHERE ptype = 'g' AND v0 = 'creator' AND v1 = 'group_user'
);

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
SELECT 'g', 'vendor', 'group_user', '', '', '', ''
WHERE NOT EXISTS (
    SELECT 1 FROM public.casbin_rule
    WHERE ptype = 'g' AND v0 = 'vendor' AND v1 = 'group_user'
);
