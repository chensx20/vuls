package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func TestParseApkInfo(t *testing.T) {
	var tests = []struct {
		in    string
		packs models.Packages
	}{
		{
			in: `musl-1.1.16-r14
busybox-1.26.2-r7
`,
			packs: models.Packages{
				"musl": {
					Name:    "musl",
					Version: "1.1.16-r14",
				},
				"busybox": {
					Name:    "busybox",
					Version: "1.26.2-r7",
				},
			},
		},
	}
	d := newAlpine(config.ServerInfo{})
	for i, tt := range tests {
		pkgs, _ := d.parseApkInfo(tt.in)
		if !reflect.DeepEqual(tt.packs, pkgs) {
			t.Errorf("[%d] expected %v, actual %v", i, tt.packs, pkgs)
		}
	}
}

func TestAlpineParseInstalledPackages(t *testing.T) {
	input := `P:libalpha
V:1.0-r0
o:alpha-src

P:libalpha-dev
V:2.0-r1
o:alpha-src

P:orphan
V:3.0-r0

P:broken
o:broken-src

V:5.0-r0
o:nameless-src

invalid record

P:final
V:4.0-r0
o:final-src`

	packages, sources, err := newAlpine(config.ServerInfo{}).parseInstalledPackages(input)
	if err != nil {
		t.Fatalf("parseInstalledPackages() error = %v", err)
	}
	if len(packages) != 4 {
		t.Fatalf("got %d packages, want 4", len(packages))
	}
	if got := sources["alpha-src"].BinaryNames; !reflect.DeepEqual(got, []string{"libalpha", "libalpha-dev"}) {
		t.Errorf("alpha-src binary names = %v", got)
	}
	wantPackages := models.Packages{
		"libalpha":     {Name: "libalpha", Version: "1.0-r0"},
		"libalpha-dev": {Name: "libalpha-dev", Version: "2.0-r1"},
		"orphan":       {Name: "orphan", Version: "3.0-r0"},
		"final":        {Name: "final", Version: "4.0-r0"},
	}
	if !reflect.DeepEqual(packages, wantPackages) {
		t.Errorf("packages = %+v, want %+v", packages, wantPackages)
	}
	wantSources := models.SrcPackages{
		"alpha-src": {Name: "alpha-src", Version: "1.0-r0", BinaryNames: []string{"libalpha", "libalpha-dev"}},
		"final-src": {Name: "final-src", Version: "4.0-r0", BinaryNames: []string{"final"}},
	}
	if !reflect.DeepEqual(sources, wantSources) {
		t.Errorf("sources = %+v, want %+v", sources, wantSources)
	}
	packages.MergeNewVersion(models.Packages{"libalpha": {Name: "libalpha", NewVersion: "1.1-r0"}})
	if packages["libalpha"].Version != "1.0-r0" || packages["libalpha"].NewVersion != "1.1-r0" || packages["libalpha-dev"].NewVersion != "2.0-r1" {
		t.Errorf("update versions not merged: %+v", packages)
	}
}

func TestAlpineParseEmptyInstalledDatabase(t *testing.T) {
	packages, sources, err := newAlpine(config.ServerInfo{}).parseInstalledPackages("")
	if err != nil || len(packages) != 0 || len(sources) != 0 {
		t.Errorf("empty database: packages=%+v sources=%+v err=%v", packages, sources, err)
	}
}

func TestAlpineServerModeUnsupported(t *testing.T) {
	_, _, err := ParseInstalledPkgs(config.Distro{Family: constant.Alpine}, models.Kernel{}, "P:busybox\nV:1.0-r0\n")
	if err == nil || err.Error() != "Server mode for alpine is not implemented yet" {
		t.Errorf("Alpine server mode error = %v", err)
	}
}

func TestParseApkVersion(t *testing.T) {
	var tests = []struct {
		in    string
		packs models.Packages
	}{
		{
			in: `Installed:                                Available:
libcrypto1.0-1.0.1q-r0                  < 1.0.2m-r0
libssl1.0-1.0.1q-r0                     < 1.0.2m-r0
nrpe-2.14-r2                            < 2.15-r5
`,
			packs: models.Packages{
				"libcrypto1.0": {
					Name:       "libcrypto1.0",
					NewVersion: "1.0.2m-r0",
				},
				"libssl1.0": {
					Name:       "libssl1.0",
					NewVersion: "1.0.2m-r0",
				},
				"nrpe": {
					Name:       "nrpe",
					NewVersion: "2.15-r5",
				},
			},
		},
	}
	d := newAlpine(config.ServerInfo{})
	for i, tt := range tests {
		pkgs, _ := d.parseApkVersion(tt.in)
		if !reflect.DeepEqual(tt.packs, pkgs) {
			t.Errorf("[%d] expected %v, actual %v", i, tt.packs, pkgs)
		}
	}
}
