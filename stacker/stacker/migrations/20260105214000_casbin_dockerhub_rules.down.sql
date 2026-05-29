DELETE FROM public.casbin_rule
WHERE v1 = '/dockerhub/namespaces' AND v2 = 'GET';

DELETE FROM public.casbin_rule
WHERE v1 = '/dockerhub/:namespace/repositories' AND v2 = 'GET';

DELETE FROM public.casbin_rule
WHERE v1 = '/dockerhub/:namespace/repositories/:repository/tags' AND v2 = 'GET';
