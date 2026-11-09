# Legacy frontend

`dashboard/` is the canonical Scrutineering frontend. The `web/` tree is
retained temporarily for migration history and should not receive new product
features.

New UI work belongs in `dashboard/` and must use the planner/API contracts in
`docs/api/`. Remove this tree after downstream consumers have migrated.
