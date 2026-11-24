package migrations

// Cells (KyIdentity C1–C5): each org's home region from its directory snapshot, and the
// cells this deployment serves, replaced at every multi-mode start (KY_CELLS).
const cellsSchema = `
ALTER TABLE tenant_directory ADD COLUMN home_region TEXT NOT NULL DEFAULT '';
CREATE TABLE served_cells (cell TEXT PRIMARY KEY);
`
