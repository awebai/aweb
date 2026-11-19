-- A human-role holder: an approver linked to a team member principal, whose
-- credential an owner act binds. It has a contact only when its role declares
-- a notice contact; every other approver keeps its contact.
ALTER TABLE {{tables.passkey_approvers}} ALTER COLUMN contact DROP NOT NULL;
ALTER TABLE {{tables.passkey_approvers}} ADD COLUMN principal TEXT
    CHECK (principal LIKE 'did:aw:_%');
ALTER TABLE {{tables.passkey_approvers}} ADD CONSTRAINT passkey_approvers_contact_or_principal
    CHECK (contact IS NOT NULL OR principal IS NOT NULL);

-- The relying party a holder's credential was bound to. NULL for a credential
-- registered through an enrolment, which is the app's own relying party.
ALTER TABLE {{tables.passkey_credentials}} ADD COLUMN rp_id TEXT;
