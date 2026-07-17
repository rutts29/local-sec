package lsec

import (
	"fmt"
	"os/exec"
	"strings"
)

func sqlQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func execSQLiteParams(dbPath, query string, params map[string]string) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	var script strings.Builder
	script.WriteString(".parameter init\n")
	for name, value := range params {
		script.WriteString(fmt.Sprintf(".parameter set %s '%s'\n", name, sqlQuote(value)))
	}
	script.WriteString(query)
	if !strings.HasSuffix(strings.TrimSpace(query), ";") {
		script.WriteString(";")
	}
	script.WriteString("\n")
	cmd := exec.Command("sqlite3", "-cmd", ".timeout 5000", dbPath)
	cmd.Stdin = strings.NewReader(script.String())
	return cmd.Run()
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !('0' <= r && r <= '9') && !('a' <= r && r <= 'f') {
			return false
		}
	}
	return true
}

func runSQLite(dbPath, sql string) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil
	}
	return exec.Command("sqlite3", "-cmd", ".timeout 5000", dbPath, sql).Run()
}
