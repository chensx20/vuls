//go:build !scanner
// +build !scanner

package oval

import (
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

// Alpine is the struct of Alpine Linux
type Alpine struct {
	Base
}

// NewAlpine creates OVAL client for SUSE
func NewAlpine(driver ovaldb.DB, baseURL string) Alpine {
	return Alpine{
		Base{
			driver:  driver,
			baseURL: baseURL,
			family:  constant.Alpine,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Alpine) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if o.driver == nil {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.baseURL); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions via HTTP. err: %w", err)
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(r, o.driver); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions from DB. err: %w", err)
		}
	}
	for _, defPacks := range relatedDefs.entries {
		if err := o.update(r, defPacks); err != nil {
			return 0, err
		}
	}

	return len(relatedDefs.entries), nil
}

func (o Alpine) update(r *models.ScanResult, defpacks defPacks) error {
	cveID := defpacks.def.Advisory.Cves[0].CveID
	vinfo, ok := r.ScannedCves[cveID]
	if !ok {
		logging.Log.Debugf("%s is newly detected by OVAL", cveID)
		vinfo = models.VulnInfo{
			CveID:       cveID,
			Confidences: []models.Confidence{models.OvalMatch},
		}
	}

	for _, pack := range defpacks.toPackStatuses() {
		var err error
		vinfo.AffectedPackages, err = mergeAlpinePackageStatus(vinfo.AffectedPackages, pack)
		if err != nil {
			return err
		}
	}
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[cveID] = vinfo
	return nil
}

func (e *ovalResult) addAlpineSourceDefinition(r *models.ScanResult, req request, def ovalmodels.Definition) error {
	for _, name := range req.binaryPackNames {
		pack, ok := r.Packages[name]
		if !ok {
			return xerrors.Errorf("Source package %s references missing binary package %s", req.packName, name)
		}
		binReq := req
		binReq.versionRelease = pack.FormatVer()
		binReq.newVersionRelease = pack.FormatNewVer()
		binReq.arch = pack.Arch
		binReq.isSrcPack = false
		affected, notFixedYet, fixState, fixedIn, err := isOvalDefAffected(def, binReq, constant.Alpine, r.Release, r.RunningKernel, r.EnabledDnfModules)
		if err != nil {
			return xerrors.Errorf("Failed to exec isOvalAffected. err: %w", err)
		}
		if affected {
			e.upsert(def, name, fixStat{
				notFixedYet: notFixedYet,
				fixState:    fixState,
				fixedIn:     fixedIn,
				isSrcPack:   true,
				srcPackName: req.packName,
			})
		}
	}
	return nil
}

func mergeAlpinePackageStatus(statuses models.PackageFixStatuses, incoming models.PackageFixStatus) (models.PackageFixStatuses, error) {
	for i, current := range statuses {
		if current.Name != incoming.Name {
			continue
		}
		current.NotFixedYet = current.NotFixedYet || incoming.NotFixedYet
		if current.FixState == "" || incoming.FixState != "" && incoming.FixState < current.FixState {
			current.FixState = incoming.FixState
		}
		if current.FixedIn == "" {
			current.FixedIn = incoming.FixedIn
		} else if incoming.FixedIn != "" {
			less, err := lessThan(constant.Alpine, current.FixedIn, ovalmodels.Package{Version: incoming.FixedIn})
			if err != nil {
				return nil, xerrors.Errorf("Failed to compare Alpine fixed versions for %s. err: %w", incoming.Name, err)
			}
			if less {
				current.FixedIn = incoming.FixedIn
			}
		}
		statuses[i] = current
		return statuses, nil
	}
	return append(statuses, incoming), nil
}
