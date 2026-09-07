#!/usr/bin/env bash
set -euo pipefail

# Failure-semantics gate. The selected tests inject the dependency failures at
# the seam where they occur; each expected result is part of the test name and
# assertion (fail closed for signer/auth/state, bounded continuation for
# telemetry, and 502 for a dead backend). The compiled harness adds real
# process termination, backend dial failure, body limits, and restart checks.
go test ./internal/statebolt -run 'Test(PostureCorruptFailsClosed|SchemaV1MigratesWithPreMigrationBackup|BackupRestoreAndCheck)'
go test ./internal/terminator -run 'Test(EvidenceStoreOutageDoesNotFailOpen|P01OutageDoesNotDowngradeConstrained|P01OutageBlockedStaysBlocked|KeyringLoadRejectsCorruptPack|PreparedRotationRequiresBackendAcceptanceBeforeActivation)'
go test ./internal/proxy -run 'Test(SourceResolutionFailureFailsClosed|ObserverSeesCompletionPersistenceFailure|SpoolBodyChunkedEndToEnd|StreamWriteIdleTimeoutDeadlineScheme|DataPlaneReservationReleasedOnSuccessAndTransportError|Strip)'
go test ./internal/config -run 'Test(BackendTLSConfigMaterial|AdminBindValidation|NoPublicAdminOverride)'
go test ./cmd/gripline -run 'TestAcceptance(AdminLifecycleRoutes|Readyz|KeysExportIsReadOnly|PepperEntropyRequired|PseudonymKeySeparation)'
bash scripts/release-harness.sh

echo "chaos smoke: bounded failure semantics passed"
