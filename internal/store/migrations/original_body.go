package migrations

// originalBodySchema keeps the envelope a message with attachments was first sent in, once it is
// edited (E5): that envelope holds the files' keys, so an edit never has to seal them again for
// whoever is in the room now.
const originalBodySchema = `
ALTER TABLE messages ADD COLUMN original_body TEXT NOT NULL DEFAULT '';
`
