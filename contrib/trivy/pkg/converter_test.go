package pkg

import (
	"testing"

	trivydbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/future-architect/vuls/models"
)

func TestConvertAggregatesContentBySource(t *testing.T) {
	results := trivyTypes.Results{{
		Type: ftypes.Debian,
		Vulnerabilities: []trivyTypes.DetectedVulnerability{
			{
				Vulnerability: trivydbTypes.Vulnerability{
					VendorSeverity: trivydbTypes.VendorSeverity{"debian": trivydbTypes.SeverityLow},
					CVSS:           trivydbTypes.VendorCVSS{"nvd": {V3Score: 7.5, V3Vector: "vector-high"}},
				},
				VulnerabilityID: "CVE-2024-0001",
				PkgName:         "openssl",
			},
			{
				Vulnerability: trivydbTypes.Vulnerability{
					VendorSeverity: trivydbTypes.VendorSeverity{"debian": trivydbTypes.SeverityMedium},
					CVSS:           trivydbTypes.VendorCVSS{"nvd": {V3Score: 9.8, V3Vector: "vector-critical"}},
				},
				VulnerabilityID: "CVE-2024-0001",
				PkgName:         "openssl",
			},
		},
	}}

	result, err := Convert(results)
	if err != nil {
		t.Fatal(err)
	}

	contents := result.ScannedCves["CVE-2024-0001"].CveContents
	if len(contents[models.CveContentType("trivy:debian")]) != 1 {
		t.Fatalf("expected one Debian content, got %d", len(contents[models.CveContentType("trivy:debian")]))
	}
	if got := contents[models.CveContentType("trivy:debian")][0].Cvss3Severity; got != "LOW|MEDIUM" {
		t.Fatalf("expected LOW|MEDIUM, got %q", got)
	}
	if got := contents[models.CveContentType("trivy:nvd")][0].Cvss3Score; got != 9.8 {
		t.Fatalf("expected highest CVSS score, got %v", got)
	}
}
