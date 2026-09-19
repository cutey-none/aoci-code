package managedscope

import (
	"fmt"

	"github.com/aoci-spec/aoci-code/internal/baseline"
	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

type SnapshotOptions struct{ HighRiskContentApproved bool }

// Snapshot hashes only index and observe paths after Safe Inventory and policy
// evaluation. Excluded content is never opened and therefore cannot enter
// Baseline, Evidence, Candidate, Prompt, or Ledger bodies through this path.
func Snapshot(repositoryRoot string, evaluation *Evaluation, options ...SnapshotOptions) (map[string]baseline.Fingerprint, error) {
	return SnapshotReusing(repositoryRoot, evaluation, nil, options...)
}

// SnapshotReusing is Snapshot with the caller's already-loaded Baseline
// fingerprints available for reuse. It hashes exactly the same paths and returns
// exactly the same fingerprints; prior only lets an unchanged Go file skip a
// reparse it cannot affect. A nil or absent prior degrades to Snapshot.
//
// The paths are hashed concurrently but consumed in evaluation order, so the
// first reported failure is the same path a serial pass would report. Reading
// stops before the first unapproved high-risk path: authorization is a content
// boundary, and hashing the rest of the batch would open content this call is
// not allowed to read.
func SnapshotReusing(repositoryRoot string, evaluation *Evaluation, prior map[string]baseline.Fingerprint, options ...SnapshotOptions) (map[string]baseline.Fingerprint, error) {
	if evaluation == nil {
		return nil, fmt.Errorf("managed_scope_evaluation_required")
	}
	approved := len(options) > 0 && options[0].HighRiskContentApproved

	candidates := make([]PathEvaluation, 0, len(evaluation.Index)+len(evaluation.Observe))
	candidates = append(candidates, evaluation.Index...)
	candidates = append(candidates, evaluation.Observe...)

	readable := len(candidates)
	for index, item := range candidates {
		if item.SafetyStatus == "high_risk_exact_opt_in" && !approved {
			readable = index
			break
		}
	}
	relPaths := make([]string, readable)
	for index := 0; index < readable; index++ {
		relPaths[index] = candidates[index].Path
	}
	outcomes := baseline.HashPathsParallel(repositoryRoot, relPaths, prior)

	result := make(map[string]baseline.Fingerprint, len(candidates))
	for index, item := range candidates {
		if item.SafetyStatus == "high_risk_exact_opt_in" && !approved {
			return nil, fmt.Errorf("managed_scope_high_risk_read_approval_required: %s", item.Path)
		}
		if outcomes[index].Err != nil {
			return nil, fmt.Errorf("managed_scope_source_unreadable: %s", item.Path)
		}
		fingerprint := outcomes[index].Fingerprint
		fingerprint.Role = item.Role
		if fingerprint.Role == machinecontract.ScopeRoleIndex || fingerprint.Role == machinecontract.ScopeRoleObserve {
			result[item.Path] = fingerprint
		}
	}
	return result, nil
}
