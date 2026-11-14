package pkg

import (
	"fmt"
	"sort"
	"strings"
	"time"

	trivydbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/future-architect/vuls/models"
)

// Convert :
func Convert(results types.Results) (result *models.ScanResult, err error) {
	scanResult := &models.ScanResult{
		JSONVersion: models.JSONVersion,
		ScannedCves: models.VulnInfos{},
	}

	pkgs := models.Packages{}
	srcPkgs := models.SrcPackages{}
	vulnInfos := models.VulnInfos{}
	uniqueLibraryScannerPaths := map[string]models.LibraryScanner{}
	for _, trivyResult := range results {
		for _, vuln := range trivyResult.Vulnerabilities {
			if _, ok := vulnInfos[vuln.VulnerabilityID]; !ok {
				vulnInfos[vuln.VulnerabilityID] = models.VulnInfo{
					CveID: vuln.VulnerabilityID,
					Confidences: models.Confidences{
						{
							Score:           100,
							DetectionMethod: models.TrivyMatchStr,
						},
					},
					AffectedPackages: models.PackageFixStatuses{},
					CveContents:      models.CveContents{},
					LibraryFixedIns:  models.LibraryFixedIns{},
					// VulnType : "",
				}
			}
			vulnInfo := vulnInfos[vuln.VulnerabilityID]
			var notFixedYet bool
			fixState := ""
			if len(vuln.FixedVersion) == 0 {
				notFixedYet = true
				fixState = "Affected"
			}
			var references models.References
			for _, reference := range vuln.References {
				references = append(references, models.Reference{
					Source: "trivy",
					Link:   reference,
				})
			}

			sort.Slice(references, func(i, j int) bool {
				return references[i].Link < references[j].Link
			})

			var published time.Time
			if vuln.PublishedDate != nil {
				published = *vuln.PublishedDate
			}

			var lastModified time.Time
			if vuln.LastModifiedDate != nil {
				lastModified = *vuln.LastModifiedDate
			}

			for source, severity := range vuln.VendorSeverity {
				contentType := models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))
				content := models.CveContent{
					Type:          models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source)),
					CveID:         vuln.VulnerabilityID,
					Title:         vuln.Title,
					Summary:       vuln.Description,
					Cvss3Severity: trivydbTypes.SeverityNames[severity],
					Published:     published,
					LastModified:  lastModified,
					References:    references,
				}
				mergeTrivyContent(vulnInfo.CveContents, contentType, content)
			}

			for source, cvss := range vuln.CVSS {
				contentType := models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))
				content := models.CveContent{
					Type:         models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source)),
					CveID:        vuln.VulnerabilityID,
					Title:        vuln.Title,
					Summary:      vuln.Description,
					Cvss2Score:   cvss.V2Score,
					Cvss2Vector:  cvss.V2Vector,
					Cvss3Score:   cvss.V3Score,
					Cvss3Vector:  cvss.V3Vector,
					Published:    published,
					LastModified: lastModified,
					References:   references,
				}
				mergeTrivyContent(vulnInfo.CveContents, contentType, content)
			}

			// do only if image type is Vuln
			if isTrivySupportedOS(trivyResult.Type) {
				pkgs[vuln.PkgName] = models.Package{
					Name:    vuln.PkgName,
					Version: vuln.InstalledVersion,
				}
				vulnInfo.AffectedPackages = append(vulnInfo.AffectedPackages, models.PackageFixStatus{
					Name:        vuln.PkgName,
					NotFixedYet: notFixedYet,
					FixState:    fixState,
					FixedIn:     vuln.FixedVersion,
				})
			} else {
				vulnInfo.LibraryFixedIns = append(vulnInfo.LibraryFixedIns, models.LibraryFixedIn{
					Key:     string(trivyResult.Type),
					Name:    vuln.PkgName,
					Path:    trivyResult.Target,
					FixedIn: vuln.FixedVersion,
				})
				libScanner := uniqueLibraryScannerPaths[trivyResult.Target]
				libScanner.Type = trivyResult.Type
				libScanner.Libs = append(libScanner.Libs, models.Library{
					Name:     vuln.PkgName,
					Version:  vuln.InstalledVersion,
					FilePath: vuln.PkgPath,
				})
				uniqueLibraryScannerPaths[trivyResult.Target] = libScanner
			}
			vulnInfos[vuln.VulnerabilityID] = vulnInfo
		}

		// --list-all-pkgs flg of trivy will output all installed packages, so collect them.
		if trivyResult.Class == types.ClassOSPkg {
			for _, p := range trivyResult.Packages {
				pv := p.Version
				if p.Release != "" {
					pv = fmt.Sprintf("%s-%s", pv, p.Release)
				}
				if p.Epoch > 0 {
					pv = fmt.Sprintf("%d:%s", p.Epoch, pv)
				}
				pkgs[p.Name] = models.Package{
					Name:    p.Name,
					Version: pv,
					Arch:    p.Arch,
				}

				v, ok := srcPkgs[p.SrcName]
				if !ok {
					sv := p.SrcVersion
					if p.SrcRelease != "" {
						sv = fmt.Sprintf("%s-%s", sv, p.SrcRelease)
					}
					if p.SrcEpoch > 0 {
						sv = fmt.Sprintf("%d:%s", p.SrcEpoch, sv)
					}
					v = models.SrcPackage{
						Name:    p.SrcName,
						Version: sv,
					}
				}
				v.AddBinaryName(p.Name)
				srcPkgs[p.SrcName] = v
			}
		} else if trivyResult.Class == types.ClassLangPkg {
			libScanner := uniqueLibraryScannerPaths[trivyResult.Target]
			libScanner.Type = trivyResult.Type
			for _, p := range trivyResult.Packages {
				libScanner.Libs = append(libScanner.Libs, models.Library{
					Name:     p.Name,
					Version:  p.Version,
					PURL:     getPURL(p),
					FilePath: p.FilePath,
				})
			}
			uniqueLibraryScannerPaths[trivyResult.Target] = libScanner
		}
	}

	// flatten and unique libraries
	libraryScanners := make([]models.LibraryScanner, 0, len(uniqueLibraryScannerPaths))
	for path, v := range uniqueLibraryScannerPaths {
		uniqueLibrary := map[string]models.Library{}
		for _, lib := range v.Libs {
			uniqueLibrary[lib.Name+lib.Version] = lib
		}

		var libraries []models.Library
		for _, library := range uniqueLibrary {
			libraries = append(libraries, library)
		}

		sort.Slice(libraries, func(i, j int) bool {
			return libraries[i].Name < libraries[j].Name
		})

		libscanner := models.LibraryScanner{
			Type:         v.Type,
			LockfilePath: path,
			Libs:         libraries,
		}
		libraryScanners = append(libraryScanners, libscanner)
	}
	sort.Slice(libraryScanners, func(i, j int) bool {
		return libraryScanners[i].LockfilePath < libraryScanners[j].LockfilePath
	})
	scanResult.ScannedCves = vulnInfos
	scanResult.Packages = pkgs
	scanResult.SrcPackages = srcPkgs
	scanResult.LibraryScanners = libraryScanners
	return scanResult, nil
}

func mergeTrivyContent(contents models.CveContents, contentType models.CveContentType, incoming models.CveContent) {
	current, found := contents[contentType]
	if !found {
		contents[contentType] = []models.CveContent{incoming}
		return
	}

	merged := current[0]
	merged.Title = mergeString(merged.Title, incoming.Title)
	merged.Summary = mergeString(merged.Summary, incoming.Summary)
	merged.Cvss3Severity = mergeTrivySeverity(contentType, merged.Cvss3Severity, incoming.Cvss3Severity)
	merged.Cvss2Score, merged.Cvss2Vector = mergeCvss(merged.Cvss2Score, merged.Cvss2Vector, incoming.Cvss2Score, incoming.Cvss2Vector)
	merged.Cvss3Score, merged.Cvss3Vector = mergeCvss(merged.Cvss3Score, merged.Cvss3Vector, incoming.Cvss3Score, incoming.Cvss3Vector)
	merged.Published = minTime(merged.Published, incoming.Published)
	merged.LastModified = maxTime(merged.LastModified, incoming.LastModified)
	merged.References = mergeReferences(merged.References, incoming.References)
	contents[contentType] = []models.CveContent{merged}
}

func mergeTrivySeverity(contentType models.CveContentType, current, incoming string) string {
	if incoming == "" {
		return current
	}
	if current == "" {
		return incoming
	}
	if contentType != models.CveContentType("trivy:debian") {
		if trivySeverityRank(incoming) > trivySeverityRank(current) {
			return incoming
		}
		return current
	}

	severities := map[string]struct{}{}
	for _, severity := range append(strings.Split(current, "|"), strings.Split(incoming, "|")...) {
		severities[severity] = struct{}{}
	}
	ordered := make([]string, 0, len(severities))
	for severity := range severities {
		ordered = append(ordered, severity)
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, right := trivySeverityRank(ordered[i]), trivySeverityRank(ordered[j])
		if left == right {
			return ordered[i] < ordered[j]
		}
		return left < right
	})
	return strings.Join(ordered, "|")
}

func trivySeverityRank(severity string) int {
	for rank, name := range trivydbTypes.SeverityNames {
		if name == severity {
			return rank
		}
	}
	return 0
}

func mergeCvss(currentScore float64, currentVector string, incomingScore float64, incomingVector string) (float64, string) {
	if currentVector != "" && incomingVector == "" {
		return currentScore, currentVector
	}
	if currentVector == "" && incomingVector != "" {
		return incomingScore, incomingVector
	}
	if incomingScore > currentScore || (incomingScore == currentScore && incomingVector < currentVector) {
		return incomingScore, incomingVector
	}
	return currentScore, currentVector
}

func mergeString(current, incoming string) string {
	if current == "" || (incoming != "" && incoming < current) {
		return incoming
	}
	return current
}

func minTime(current, incoming time.Time) time.Time {
	if current.IsZero() || (!incoming.IsZero() && incoming.Before(current)) {
		return incoming
	}
	return current
}

func maxTime(current, incoming time.Time) time.Time {
	if incoming.After(current) {
		return incoming
	}
	return current
}

func mergeReferences(current, incoming models.References) models.References {
	byLink := map[string]models.Reference{}
	for _, reference := range append(current, incoming...) {
		byLink[reference.Link] = reference
	}
	merged := make(models.References, 0, len(byLink))
	for _, reference := range byLink {
		merged = append(merged, reference)
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Link < merged[j].Link
	})
	return merged
}

func isTrivySupportedOS(family ftypes.TargetType) bool {
	supportedFamilies := map[ftypes.TargetType]struct{}{
		ftypes.Alma:               {},
		ftypes.Alpine:             {},
		ftypes.Amazon:             {},
		ftypes.CBLMariner:         {},
		ftypes.CentOS:             {},
		ftypes.Chainguard:         {},
		ftypes.Debian:             {},
		ftypes.Fedora:             {},
		ftypes.OpenSUSE:           {},
		ftypes.OpenSUSELeap:       {},
		ftypes.OpenSUSETumbleweed: {},
		ftypes.Oracle:             {},
		ftypes.Photon:             {},
		ftypes.RedHat:             {},
		ftypes.Rocky:              {},
		ftypes.SLES:               {},
		ftypes.Ubuntu:             {},
		ftypes.Wolfi:              {},
	}
	_, ok := supportedFamilies[family]
	return ok
}

func getPURL(p ftypes.Package) string {
	if p.Identifier.PURL == nil {
		return ""
	}
	return p.Identifier.PURL.String()
}
