# Admit rules

Reuse `load_bundle`, `load_policy`, and `load_keys`. Certificates are a JSON IR, not PEM. Each certificate has `id`, `tbs`, and `sig`. The keyring maps a key id (the signer's `ski`) to a hex HMAC-SHA256 key. `sig.mac` is lowercase hex over the canonical TBS: `json.dumps(tbs, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` encoded as UTF-8. This lab does not use ASN.1 or the `cryptography` package.

The bundle names a `leaf_id`, a `hostname`, `trust_anchors` (certificate ids), and `now`.

## Path building

A parent of a certificate is a certificate whose `tbs.subject` equals the child's `tbs.issuer`. If the child has `tbs.aki` and the parent has `tbs.ski`, those values must also match. The path is written leaf-first and must end at a trust anchor. Reject `no_chain` if no such path exists.

Verify every signature, including a self-signed anchor, with the issuer's key (the parent's `ski`, or the anchor's own `ski`). A bad or missing MAC is `bad_signature`.

Prefer a path that validates cleanly; if every candidate fails, report the first path's reason codes.

## Time, CA, key usage, pathLen

`now` must satisfy `not_before <= now <= not_after` on every certificate (`not_yet_valid`, `expired`).

The leaf must have `basic_constraints.ca` false (`leaf_is_ca` otherwise) and `key_usage` must include `digitalSignature` or `keyEncipherment` (`leaf_ku`).

Every issuer, including the anchor, must have `basic_constraints.ca` true (`ca_required`) and `key_usage` must include `keyCertSign` (`ca_missing_keycertsign`).

`basic_constraints.path_len`, when present on a CA, limits how many *non-self-issued* CAs may appear between that CA and the leaf (not counting the leaf, and not counting a CA whose subject equals its parent's subject). More than `path_len` is `pathlen_exceeded`.

## EKU and unknown critical extensions

The leaf `eku` must include `serverAuth` or `anyExtendedKeyUsage` (`eku_missing`). If a CA lists a non-empty `eku` that does not include `anyExtendedKeyUsage`, the leaf EKU set must be a subset of the CA EKU set (`eku_nest`). A CA with empty EKU or with `anyExtendedKeyUsage` does not constrain the leaf.

`tbs.critical` names extensions. Known names are: `basic_constraints`, `key_usage`, `eku`, `san`, `name_constraints`, `certificate_policies`, `policy_constraints`, `inhibit_any_policy`, `ski`, `aki`. Any other critical name is `unknown_critical`.

## Name constraints and hostname

Collect names from the leaf SAN (`san.dns`, `san.email`, `san.uri`, `san.directory`). If there is no DNS SAN, the subject `cn=` (first CN in the comma-separated subject) is treated as a DNS name.

Each CA `name_constraints` is applied to those leaf names. Excluded subtrees are checked first and always win. A DNS constraint `example.com` matches that name and any subdomain at a label boundary (`www.example.com` yes, `example.com.evil.test` no, `notexample.com` no). An email constraint `@example.com` matches any local part at that domain; a constraint without `@` must be an exact address. A URI is checked on its host as a DNS name; an excluded/permitted value that contains `://` is a URI prefix instead. Directory names match when the leaf name equals the constraint or ends with `,` plus the constraint.

If a type has a non-empty *permitted* set, every leaf name of that type must match at least one permitted constraint. URI names may also be permitted by `permitted.dns` when no `permitted.uri` matches. A failed constraint is `name_constraint`.

The bundle hostname must match a leaf DNS name. A wildcard `*.shop.example.com` matches exactly one label in that position and no other depth. If the hostname does not match, `hostname_mismatch`. When a DNS SAN is present, the CN is not used for hostname matching (it is only a fallback when SAN DNS is empty).

## Certificate policies

`policy.require_policy`, when set, must appear in the effective policy set of the path. Each certificate contributes `certificate_policies`, or `{2.5.29.32.0}` (anyPolicy) if the list is empty. If any certificate has `inhibit_any_policy` set to a non-null value, anyPolicy is removed from every set and no longer fills a gap. The effective set is the intersection of the remaining sets, except a set that still contains anyPolicy (and inhibition is off) does not shrink the intersection. If the required OID is absent and anyPolicy is not in the effective set, that is `policy_oid`.

## Report and exit

Report: `decision`, `reason_codes`, `path` (leaf-first ids), `notes`. Stable reason order: `no_chain`, `bad_signature`, `not_yet_valid`, `expired`, `ca_required`, `leaf_is_ca`, `ca_missing_keycertsign`, `leaf_ku`, `pathlen_exceeded`, `eku_missing`, `eku_nest`, `unknown_critical`, `name_constraint`, `hostname_mismatch`, `policy_oid`.

`allow` exits 0, `deny` exits 1, load failures exit 2.

## Public fixtures

`--policy fixtures/policy.json --keys fixtures/keys.json --bundle fixtures/bundles/NAME.json`:

- `ok-chain.json` → allow
- `excluded-dns.json` → deny `name_constraint`
- `not-permitted.json` → deny `name_constraint`
- `pathlen.json` → deny `pathlen_exceeded`
- `eku-nest.json` → deny `eku_nest`
- `unknown-critical.json` → deny `unknown_critical`
- `expired-intermediate.json` → deny `expired`
- `hostname-mismatch.json` → deny `hostname_mismatch`
- `policy-missing.json` → deny `policy_oid`
