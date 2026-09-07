package terminator

import "github.com/B-A-M-N/gripline/internal/lane"

// laneFeatures returns a lane feature vector carrying the full trusted source
// identity (ASN + network type + region + client family ≈ 0.80 of the feature
// space), so P0.9's comparable-weight floor (0.70) lets repeated requests on
// the same lane legitimately MATCH their established lane. Tests that formerly
// used a bare {ASN} or {ASN, NetworkType} vector relied on the pre-P0.9
// renormalization that let a sparse candidate collapse into an established
// lane — exactly the laundering strategy P0.9 now forbids.
func laneFeatures(asn string) lane.Features {
	return lane.Features{
		NetworkASN:   asn,
		NetworkType:  "residential",
		RegionClass:  "us",
		ClientFamily: "claude-code",
	}
}
