-- +goose Up

UPDATE memberships m
SET 
    subject = r.id,
    subject_type = 'role'
FROM roles r
WHERE 
    r.org_id = m.org_id 
    AND r.display_name = 'Admin'
    AND m.subject_type = 'virtual-group' 
    AND m.subject = 'owners';

ALTER TABLE memberships ADD COLUMN role uuid;
ALTER TABLE memberships ADD CONSTRAINT fk_memberships_role_org_id FOREIGN KEY(role, org_id) REFERENCES roles(id, org_id);

UPDATE invitations i
SET 
    membership_subject = r.id,
    membership_subject_type = 'role'
FROM roles r
WHERE 
    r.org_id = i.org_id 
    AND r.display_name = 'Admin'
    AND i.membership_subject_type = 'virtual-group' 
    AND i.membership_subject = 'owners';

-- +goose Down

ALTER TABLE memberships DROP CONSTRAINT fk_memberships_role_org_id IF EXISTS;
ALTER TABLE memberships DROP COLUMN role IF EXISTS;
