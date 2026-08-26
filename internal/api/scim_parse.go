package api

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// scimFilterResult is the parsed form of a simple "attr eq value" filter.
type scimFilterResult struct {
	Attr  string // normalised to lower-case
	Value string
}

// scimFilterRegexp matches exactly `attr eq "value"` (RFC 7644 §3.4.2.2 subset).
var scimFilterRegexp = regexp.MustCompile(`(?i)^(\w+)\s+eq\s+"([^"]*)"$`)

// parseScimFilter parses the supported subset of SCIM filter expressions.
// Only `attr eq "value"` is accepted; anything else returns a non-nil error.
func parseScimFilter(filter string) (*scimFilterResult, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil, nil
	}
	m := scimFilterRegexp.FindStringSubmatch(filter)
	if m == nil {
		return nil, fmt.Errorf("unsupported filter expression (only 'attr eq \"value\"' is supported): %q", filter)
	}
	return &scimFilterResult{Attr: strings.ToLower(m[1]), Value: m[2]}, nil
}

// bracketMemberRegexp matches the Entra path form `members[value eq "id"]` and
// captures the scim user id so we can reduce it to a plain remove-by-id op.
var bracketMemberRegexp = regexp.MustCompile(`(?i)^members\[value\s+eq\s+"([^"]*)"\]$`)

// normalizedScimPatchOp is a parsed, normalised PATCH operation ready for execution.
type normalizedScimPatchOp struct {
	Op   string // always lower-case: "add", "replace", "remove"
	Path string // lower-case attribute name or "" for pathless ops
	// Scalar value fields (set at most one per op):
	StrValue  *string
	BoolValue *bool
	// Member list (for add/remove on members path):
	MemberIds []uuid.UUID
	// Object-style value map (for pathless replace, e.g. Okta):
	Attrs map[string]interface{}
	// If true, Path was a bracket member filter (`members[value eq "id"]`)
	// and MemberIds contains the single member to remove.
	IsBracketMemberRemove bool
}

// normalizePatchOps expands a raw scimPatchRequest into a flat slice of
// normalizedScimPatchOps, resolving all IDP quirks:
//
//   - Entra: capitalised op names → lower-cased.
//   - Entra: string booleans → Go bool.
//   - Entra: `members[value eq "id"]` bracket filter path → IsBracketMemberRemove.
//   - Okta: pathless `{op:"replace", value:{attr:val,...}}` → per-attribute entries.
func normalizePatchOps(req scimPatchRequest) ([]normalizedScimPatchOp, error) {
	out := make([]normalizedScimPatchOp, 0, len(req.Operations))
	for _, raw := range req.Operations {
		op := raw.normalizedOp()
		if op != scimOpAdd && op != scimOpReplace && op != scimOpRemove {
			return nil, fmt.Errorf("unknown PATCH op %q", raw.Op)
		}

		path := strings.ToLower(strings.TrimSpace(raw.Path))

		// Entra bracket form: `members[value eq "id"]`
		if bm := bracketMemberRegexp.FindStringSubmatch(path); bm != nil {
			memberId, err := uuid.Parse(bm[1])
			if err != nil {
				return nil, fmt.Errorf("invalid member id in bracket path %q: %w", raw.Path, err)
			}
			out = append(out, normalizedScimPatchOp{
				Op:                    scimOpRemove,
				Path:                  scimAttrMembers,
				MemberIds:             []uuid.UUID{memberId},
				IsBracketMemberRemove: true,
			})
			continue
		}

		// Pathless op whose value is an object → Okta style; expand into per-attribute ops.
		if path == "" && len(raw.Value) > 0 {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw.Value, &obj); err == nil && len(obj) > 0 {
				for k, v := range obj {
					norm, err := buildScalarOp(op, strings.ToLower(k), v)
					if err != nil {
						return nil, err
					}
					if norm != nil {
						out = append(out, *norm)
					}
				}
				continue
			}
		}

		// Path-based op with a members list value.
		if path == scimAttrMembers && len(raw.Value) > 0 {
			ids, err := parseMemberValueList(raw.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid members value: %w", err)
			}
			out = append(out, normalizedScimPatchOp{Op: op, Path: scimAttrMembers, MemberIds: ids})
			continue
		}

		// Ordinary scalar path-based op.
		if path != "" {
			norm, err := buildScalarOp(op, path, raw.Value)
			if err != nil {
				return nil, err
			}
			if norm != nil {
				out = append(out, *norm)
			}
			continue
		}

		// No path and value is not an object → skip (unknown pathless op).
	}
	return out, nil
}

// buildScalarOp constructs a normalizedScimPatchOp for a single scalar attribute.
// Returns nil for unknown attributes (they are silently ignored per spec).
func buildScalarOp(op, attr string, rawVal json.RawMessage) (*normalizedScimPatchOp, error) {
	norm := normalizedScimPatchOp{Op: op, Path: attr}
	if len(rawVal) == 0 {
		return &norm, nil
	}

	switch attr {
	case scimAttrActive:
		var b boolOrString
		if err := json.Unmarshal(rawVal, &b); err != nil {
			return nil, fmt.Errorf("invalid value for active: %w", err)
		}
		bv := bool(b)
		norm.BoolValue = &bv
	case scimAttrUserName, scimAttrDisplayName, scimAttrExternalId:
		var s string
		if err := json.Unmarshal(rawVal, &s); err != nil {
			return nil, fmt.Errorf("invalid string value for %s: %w", attr, err)
		}
		norm.StrValue = &s
	default:
		// Unknown attribute — ignore silently (Entra sends many we don't store).
		return nil, nil
	}
	return &norm, nil
}

// parseMemberValueList decodes `[{"value":"<id>"},...]`.
func parseMemberValueList(raw json.RawMessage) ([]uuid.UUID, error) {
	var entries []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(entries))
	for _, e := range entries {
		id, err := uuid.Parse(e.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid member value uuid %q: %w", e.Value, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}
