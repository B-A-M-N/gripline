// Package gates implements the executable acceptance gates (spec §111, §112).
// Each Gate in the product's release contract — A through J — maps to a
// runnable proof that FAILS the build if the security property regresses.
//
// The gates are deliberately cross-cutting: they exercise real packages against
// each other (terminator + proxy + registry + resource + evidence) rather than
// testing units in isolation, so a regression in any seam that would violate
// the contract surfaces here before release.
package gates