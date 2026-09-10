package statepg

import (
	"strconv"

	"github.com/B-A-M-N/gripline/internal/resource"
)

// sourceIdentityReferencePredicate returns the shared SQL predicate for
// source-scoped state. It is used by both alias maintenance and pseudonym
// retirement so cleanup cannot silently define a weaker reference set than
// crypto lifecycle safety.
func sourceIdentityReferencePredicate(sourceExpression string) string {
	return `(
		EXISTS (SELECT 1 FROM gripline_resource_source_scopes
			WHERE scope_id=` + sourceExpression + `)
		OR EXISTS (SELECT 1 FROM gripline_resource_buckets
			WHERE scope=` + resourceScopeSourceSQL() + ` AND scope_id=` + sourceExpression + `)
		OR EXISTS (SELECT 1 FROM gripline_evidence
			WHERE scope='SOURCE' AND subject_id=` + sourceExpression + `)
		OR EXISTS (SELECT 1 FROM gripline_evidence_guards
			WHERE scope='SOURCE' AND subject_id=` + sourceExpression + `)
		OR EXISTS (SELECT 1 FROM gripline_adaptive_window_subjects
			WHERE subject=` + sourceExpression + `)
		OR EXISTS (SELECT 1 FROM gripline_adaptive_baselines
			WHERE subject=` + sourceExpression + `)
	)`
}

func resourceScopeSourceSQL() string {
	return strconv.Itoa(int(resource.ScopeSource))
}
