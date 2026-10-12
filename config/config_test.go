package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func passwordFixture(t *testing.T) (*Manager, string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("previous-fixture-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	m := &Manager{path: path, cfg: Config{
		WebUser: "fixture-admin", WebPassHash: string(hash), Token: "fixture-token",
		VirtType: "incus", IPv6Subnet: "2001:db8::/64",
	}}
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	return m, path
}

func TestSetWebPasswordHashesLiteralSpecialCharacters(t *testing.T) {
	for _, password := range []string{
		"FixtureOnly!star*literal*Z9", `  fixture\\literal!*$()'"  `,
		"$2-not-an-existing-hash", "测试密码八个字符以上", strings.Repeat("a", 72),
	} {
		t.Run(password, func(t *testing.T) {
			m, path := passwordFixture(t)
			previous := m.Get()
			if err := m.SetWebPassword(password); err != nil {
				t.Fatal(err)
			}
			if err := bcrypt.CompareHashAndPassword([]byte(m.Get().WebPassHash), []byte(password)); err != nil {
				t.Fatal("saved hash does not match the literal input")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var saved Config
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			if err := bcrypt.CompareHashAndPassword([]byte(saved.WebPassHash), []byte(password)); err != nil {
				t.Fatal("configuration contains no valid password hash")
			}
			if bytes.Contains(data, []byte(password)) {
				t.Fatal("plaintext password persisted")
			}
			saved.WebPassHash = previous.WebPassHash
			if saved != previous {
				t.Fatal("unrelated configuration changed")
			}
		})
	}
}

func TestSetWebPasswordRejectsInvalidInputWithoutChanges(t *testing.T) {
	for _, password := range []string{"", "short", strings.Repeat("a", 73), strings.Repeat("密", 25), "invalid\xffutf8"} {
		m, path := passwordFixture(t)
		before, _ := os.ReadFile(path)
		previous := m.Get()
		if err := m.SetWebPassword(password); err == nil {
			t.Fatal("invalid password accepted")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) || m.Get() != previous {
			t.Fatal("invalid password changed configuration")
		}
	}
}

func TestSetWebPasswordReportsSaveFailure(t *testing.T) {
	m := &Manager{path: filepath.Join(t.TempDir(), "missing", "config.json")}
	if err := m.SetWebPassword("fixture-new-password"); err == nil {
		t.Fatal("configuration write error ignored")
	}
}
