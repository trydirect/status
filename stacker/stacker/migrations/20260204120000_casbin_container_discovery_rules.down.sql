-- Remove Casbin rules for container discovery and import endpoints

DELETE FROM public.casbin_rule WHERE ptype='p' AND v1='/api/v1/project/:id/containers/discover' AND v2='GET';
DELETE FROM public.casbin_rule WHERE ptype='p' AND v1='/api/v1/project/:id/containers/import' AND v2='POST';
