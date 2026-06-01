-- Add down migration script here
DELETE FROM casbin_rule
WHERE ptype = 'p' and v0 = 'group_user' and v1 = '/rating/:id' and v2 = 'PUT';

DELETE FROM casbin_rule
WHERE ptype = 'p' and v0 = 'group_admin' and v1 = '/admin/rating/:id' and v2 = 'PUT';

DELETE FROM casbin_rule
WHERE ptype = 'p' and v0 = 'group_user' and v1 = '/rating/:id' and v2 = 'DELETE';

DELETE FROM casbin_rule
WHERE ptype = 'p' and v0 = 'group_admin' and v1 = '/admin/rating/:id' and v2 = 'DELETE';

DELETE FROM casbin_rule
WHERE ptype = 'p' and v0 = 'group_admin' and v1 = '/admin/rating/:id' and v2 = 'GET';

DELETE FROM casbin_rule
WHERE ptype = 'p' and v0 = 'group_admin' and v1 = '/admin/rating' and v2 = 'GET';
