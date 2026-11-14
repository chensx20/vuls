//go:build !scanner
// +build !scanner

package oval

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"testing"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

func TestAlpineUpdateMergesEmptyIDDefinitions(t *testing.T) {
	contents := models.CveContents{models.Nvd: {{Title: "existing advisory", Summary: "retain this metadata"}}}
	result := &models.ScanResult{ScannedCves: models.VulnInfos{
		"CVE-2024-0001": {CveID: "CVE-2024-0001", Confidences: models.Confidences{models.OvalMatch}, CveContents: contents},
	}}
	client := Alpine{}
	for _, name := range []string{"zlib", "libcrypto", "zlib"} {
		if err := client.update(result, defPacks{
			def:           ovalmodels.Definition{Advisory: ovalmodels.Advisory{Cves: []ovalmodels.Cve{{CveID: "CVE-2024-0001"}}}},
			binpkgFixstat: map[string]fixStat{name: {}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := result.ScannedCves["CVE-2024-0001"].AffectedPackages
	want := models.PackageFixStatuses{{Name: "libcrypto"}, {Name: "zlib"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AffectedPackages = %v, want %v", got, want)
	}
	if got := result.ScannedCves["CVE-2024-0001"].CveContents; !reflect.DeepEqual(got, contents) {
		t.Errorf("CveContents = %+v, want %+v", got, contents)
	}
}

func TestAlpineMergeOrdering(t *testing.T) {
	statuses := []models.PackageFixStatus{
		{Name: "zlib", FixedIn: "1.2-r0"},
		{Name: "libcrypto", FixedIn: "2.0-r0"},
		{Name: "zlib", FixedIn: "1.10-r0", NotFixedYet: true},
		{Name: "zlib", FixedIn: "1.2-r0"},
	}
	want := models.PackageFixStatuses{
		{Name: "libcrypto", FixedIn: "2.0-r0"},
		{Name: "zlib", FixedIn: "1.10-r0", NotFixedYet: true},
	}
	for _, reverse := range []bool{false, true} {
		r := &models.ScanResult{ScannedCves: models.VulnInfos{}}
		client := Alpine{}
		for i := range statuses {
			if reverse {
				i = len(statuses) - 1 - i
			}
			status := statuses[i]
			if err := client.update(r, defPacks{
				def:           ovalmodels.Definition{Advisory: ovalmodels.Advisory{Cves: []ovalmodels.Cve{{CveID: "CVE-2024-0001"}}}},
				binpkgFixstat: map[string]fixStat{status.Name: {fixedIn: status.FixedIn, notFixedYet: status.NotFixedYet}},
			}); err != nil {
				t.Fatal(err)
			}
		}
		if got := r.ScannedCves["CVE-2024-0001"].AffectedPackages; !reflect.DeepEqual(got, want) {
			t.Errorf("reverse=%t: packages = %+v, want %+v", reverse, got, want)
		}
	}
}

type alpineTestDB struct {
	ovaldb.DB
	definitions map[string][]ovalmodels.Definition
}

func (d alpineTestDB) GetByPackName(_, _, name, _ string) ([]ovalmodels.Definition, error) {
	return d.definitions[name], nil
}

func TestAlpineSourceAdvisories(t *testing.T) {
	definition := func(source, cve string) ovalmodels.Definition {
		return ovalmodels.Definition{
			Title:         "source advisory",
			Advisory:      ovalmodels.Advisory{Cves: []ovalmodels.Cve{{CveID: cve}}},
			AffectedPacks: []ovalmodels.Package{{Name: source, Version: "1.2-r0"}},
		}
	}
	definitions := map[string][]ovalmodels.Definition{
		"alpha-src": {definition("alpha-src", "CVE-2024-0001"), definition("alpha-src", "CVE-2024-0001"), definition("alpha-src", "CVE-2024-0002")},
		"beta-src":  {definition("beta-src", "CVE-2024-0001")},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(definitions[path.Base(r.URL.Path)]); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	for _, transport := range []string{"db", "http"} {
		for _, sourceVersion := range []string{"1.0-r0", "9.0-r0"} {
			t.Run(transport+"/"+sourceVersion, func(t *testing.T) {
				r := &models.ScanResult{
					Family: constant.Alpine, Release: "3.20",
					Packages: models.Packages{
						"libalpha":       {Name: "libalpha", Version: "1.1-r0", NewVersion: "1.3-r0"},
						"libalpha-dev":   {Name: "libalpha-dev", Version: "1.0-r0", NewVersion: "1.0-r0"},
						"libalpha-fixed": {Name: "libalpha-fixed", Version: "1.2-r0"},
						"libbeta":        {Name: "libbeta", Version: "1.1-r0"},
					},
					SrcPackages: models.SrcPackages{
						"alpha-src": {Name: "alpha-src", Version: sourceVersion, BinaryNames: []string{"libalpha", "libalpha-dev", "libalpha-fixed"}},
						"beta-src":  {Name: "beta-src", Version: sourceVersion, BinaryNames: []string{"libbeta"}},
					},
					ScannedCves: models.VulnInfos{},
				}
				var related ovalResult
				var err error
				if transport == "db" {
					related, err = getDefsByPackNameFromOvalDB(r, alpineTestDB{definitions: definitions})
				} else {
					related, err = getDefsByPackNameViaHTTP(r, server.URL)
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(related.entries) != 7 {
					t.Fatalf("got %d definition matches, want 7", len(related.entries))
				}
				client := Alpine{}
				for _, entry := range related.entries {
					for name, status := range entry.binpkgFixstat {
						if !status.isSrcPack || status.srcPackName != map[string]string{"libalpha": "alpha-src", "libalpha-dev": "alpha-src", "libbeta": "beta-src"}[name] {
							t.Errorf("source attribution for %s: %+v", name, status)
						}
					}
					if entry.def.Title != "source advisory" {
						t.Errorf("lost advisory metadata: %+v", entry.def)
					}
					if err := client.update(r, entry); err != nil {
						t.Fatal(err)
					}
				}
				want := models.PackageFixStatuses{
					{Name: "libalpha", FixedIn: "1.2-r0"},
					{Name: "libalpha-dev", FixedIn: "1.2-r0", NotFixedYet: true},
					{Name: "libbeta", FixedIn: "1.2-r0"},
				}
				if got := r.ScannedCves["CVE-2024-0001"].AffectedPackages; !reflect.DeepEqual(got, want) {
					t.Errorf("affected packages = %+v, want %+v", got, want)
				}
				if got := r.ScannedCves["CVE-2024-0002"].AffectedPackages; !reflect.DeepEqual(got, want[:2]) {
					t.Errorf("second CVE packages = %+v, want %+v", got, want[:2])
				}
			})
		}
	}
}

func TestNonAlpineSourceVersionAssessment(t *testing.T) {
	r := &models.ScanResult{
		Family: constant.Debian, Release: "12",
		Packages:    models.Packages{"binary": {Name: "binary", Version: "9.0"}},
		SrcPackages: models.SrcPackages{"source": {Name: "source", Version: "1.0", BinaryNames: []string{"binary"}}},
	}
	def := ovalmodels.Definition{DefinitionID: "debian:1", AffectedPacks: []ovalmodels.Package{{Name: "source", Version: "2.0"}}}
	related, err := getDefsByPackNameFromOvalDB(r, alpineTestDB{definitions: map[string][]ovalmodels.Definition{"source": {def}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(related.entries) != 1 {
		t.Fatalf("got %d matches, want 1", len(related.entries))
	}
	if got := related.entries[0].binpkgFixstat["binary"]; !got.isSrcPack || got.srcPackName != "source" || got.fixedIn != "2.0" {
		t.Errorf("source status = %+v", got)
	}
}
