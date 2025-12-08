# Fixture set for proof + verification key compatibility

These fixtures document previously shipped proof and verification key (VK) payloads.
They are intentionally small to keep CI traffic light while still exercising
roundtrip and rotation checks.

- Each version lives in its own folder (`v1`, `v2`, ...).
- `metadata.json` tracks size/latency signals and migration tags.
- `proof.json` and `vk.json` capture the API contract we expect to honor.

The CI helper scripts consume these fixtures when validating roundtrip logic,
migration compatibility, and performance thresholds. Update the metadata values
whenever a historical proof/VK pair changes so the guards stay meaningful.
