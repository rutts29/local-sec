package lsec

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func ParseRequirementsFiles(files []string) ([]PackageSpec, []Finding) {
	var specs []PackageSpec
	var findings []Finding
	for _, file := range files {
		found, fileFindings := parseRequirementsFile(file)
		specs = append(specs, found...)
		findings = append(findings, fileFindings...)
	}
	return specs, findings
}

func parseRequirementsFile(path string) ([]PackageSpec, []Finding) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, []Finding{{Code: "requirements_read_failed", Severity: "block", File: path, Message: "could not read requirements file", Evidence: err.Error()}}
	}
	defer f.Close()
	var specs []PackageSpec
	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNo := 0
	startLine := 0
	var continued strings.Builder
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(stripRequirementComment(scanner.Text()))
		if raw == "" {
			continue
		}
		if continued.Len() == 0 {
			startLine = lineNo
		}
		hasContinuation := strings.HasSuffix(raw, `\`)
		if hasContinuation {
			raw = strings.TrimSpace(strings.TrimSuffix(raw, `\`))
		}
		if continued.Len() > 0 {
			continued.WriteByte(' ')
		}
		continued.WriteString(raw)
		if hasContinuation {
			continue
		}
		spec, lineFindings := parseRequirementLine(path, startLine, continued.String())
		continued.Reset()
		if spec.Name != "" {
			specs = append(specs, spec)
		}
		findings = append(findings, lineFindings...)
	}
	if continued.Len() > 0 {
		findings = append(findings, Finding{Code: "requirements_continuation_unclosed", Severity: "block", File: path + ":" + strconvItoa(startLine), Message: "requirements entry has an unclosed line continuation", Evidence: continued.String()})
	}
	if err := scanner.Err(); err != nil {
		findings = append(findings, Finding{Code: "requirements_read_failed", Severity: "block", File: path, Message: "could not read requirements file", Evidence: err.Error()})
	}
	return specs, findings
}

func parseRequirementLine(path string, lineNo int, raw string) (PackageSpec, []Finding) {
	file := path + ":" + strconvItoa(lineNo)
	lower := strings.ToLower(raw)
	if strings.HasPrefix(raw, "-") || strings.HasPrefix(lower, "git+") || strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return PackageSpec{}, []Finding{{Code: "requirements_unsafe_entry", Severity: "block", File: file, Message: "requirements entry uses an option, URL, or VCS source that is not safe for pinned wheel-only mode", Evidence: raw}}
	}
	if strings.Contains(raw, ";") {
		return PackageSpec{}, []Finding{{Code: "requirements_marker_entry", Severity: "block", File: file, Message: "requirements entry uses environment markers that are not expanded by this MVP", Evidence: raw}}
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return PackageSpec{}, nil
	}
	requirement := fields[0]
	if !strings.Contains(requirement, "==") {
		return PackageSpec{}, []Finding{{Code: "requirements_unpinned_entry", Severity: "block", File: file, Message: "requirements entry must be pinned with ==", Evidence: raw}}
	}
	if findings := validateRequirementHashes(path, lineNo, raw, fields[1:]); len(findings) > 0 {
		return PackageSpec{}, findings
	}
	spec := ParsePackageSpec(requirement)
	if spec.Name == "" || spec.Version == "" || strings.ContainsAny(spec.Version, "<>~=!* ") {
		return PackageSpec{}, []Finding{{Code: "requirements_unpinned_entry", Severity: "block", File: file, Message: "requirements entry must be an exact pinned version", Evidence: raw}}
	}
	return spec, nil
}

func validateRequirementHashes(path string, lineNo int, raw string, fields []string) []Finding {
	file := path + ":" + strconvItoa(lineNo)
	hasHash := false
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		value := ""
		switch {
		case strings.HasPrefix(field, "--hash="):
			value = strings.TrimPrefix(field, "--hash=")
		case field == "--hash" && i+1 < len(fields):
			i++
			value = fields[i]
		default:
			return []Finding{{Code: "requirements_unsafe_entry", Severity: "block", File: file, Message: "requirements entry uses an option other than --hash", Evidence: raw}}
		}
		if !validRequirementSHA256Hash(value) {
			return []Finding{{Code: "requirements_invalid_hash", Severity: "block", File: file, Message: "requirements entry must use sha256 hashes", Evidence: raw}}
		}
		hasHash = true
	}
	if !hasHash {
		return []Finding{{Code: "requirements_missing_hash", Severity: "block", File: file, Message: "requirements entry must include at least one sha256 hash", Evidence: raw}}
	}
	return nil
}

func validRequirementSHA256Hash(value string) bool {
	prefix := "sha256:"
	if !strings.HasPrefix(strings.ToLower(value), prefix) {
		return false
	}
	hexDigest := value[len(prefix):]
	if len(hexDigest) != 64 {
		return false
	}
	for _, r := range hexDigest {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func stripRequirementComment(line string) string {
	if strings.HasPrefix(strings.TrimSpace(line), "#") {
		return ""
	}
	if idx := strings.Index(line, " #"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
