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
		OR EXISTS (SELECT 1 FROM gripline_adaptive_window_keys
			WHERE detector='source_novelty_source' AND observation_key=` + sourceExpression + `)
	)`
}

// usableRetainedSourceAliasPredicate identifies a retained alias whose
// pseudonym generation is still loaded by the authority. Retired-generation
// rows remain useful for cleanup history, but cannot prove cryptographic
// continuity for another generation's retirement.
func usableRetainedSourceAliasPredicate(sourceExpression, excludedGenerationExpression string) string {
	return `EXISTS (SELECT 1 FROM gripline_source_aliases retained
		JOIN gripline_cluster_crypto_generations g
		  ON g.kind='pseudonym' AND g.generation=retained.generation
		WHERE retained.canonical_source_id=` + sourceExpression + `
		  AND retained.generation<>` + excludedGenerationExpression + `
		  AND g.state IN ('active','loaded'))`
}

func resourceScopeSourceSQL() string {
	return strconv.Itoa(int(resource.ScopeSource))
}
