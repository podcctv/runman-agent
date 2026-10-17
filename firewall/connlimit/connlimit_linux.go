//go:build linux

package connlimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

const chainName = "NARWHAL_CLIMIT"

var policyIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Policy struct {
	ID         string   `json:"id"`
	VMID       string   `json:"vm_id"`
	InstanceID string   `json:"instance_id"`
	Max        int      `json:"max_connections"`
	ExpiresAt  int64    `json:"expires_at"`
	IPs        []string `json:"ips"`
	RemoveOnly bool     `json:"remove_only,omitempty"`
}

type state struct {
	Policies []Policy `json:"policies"`
}

// Runner is injectable so rule construction and rollback can be tested without
// changing the host firewall.
type Runner func(name string, args ...string) ([]byte, error)

type Manager struct {
	path       string
	configPath string
	executable string
	run        Runner
	mu         sync.Mutex
}

type Target struct {
	Managed    bool
	Running    bool
	InstanceID string
	IPs        []string
}

type Resolver func(context.Context, string) (Target, error)

func New(path, configPath, executable string) *Manager {
	return newManager(path, configPath, executable, func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	})
}

func newManager(path, configPath, executable string, runner Runner) *Manager {
	return &Manager{path: path, configPath: configPath, executable: executable, run: runner}
}

func (m *Manager) Apply(p Policy) error {
	if err := validatePolicy(p); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.withFileLock(func() error {
		st, err := m.load()
		if err != nil {
			return err
		}
		for _, old := range st.Policies {
			if old.ID == p.ID {
				if old.VMID != p.VMID || old.InstanceID != p.InstanceID || old.Max != p.Max {
					return errors.New("policy ID already exists with different contents")
				}
				if old.RemoveOnly {
					return errors.New("connection-limit policy cleanup is pending")
				}
				if err := m.installRules(old); err != nil {
					return err
				}
				if err := m.scheduleExpiry(old); err != nil {
					return m.retirePolicy(&st, old, err)
				}
				return nil
			}
			if old.VMID == p.VMID && old.InstanceID == p.InstanceID && old.ExpiresAt > time.Now().Unix() {
				return errors.New("an unexpired connection limit already exists for this instance")
			}
		}
		st.Policies = append(st.Policies, p)
		if err := m.save(st); err != nil {
			return err
		}
		if err := m.installRules(p); err != nil {
			return m.retirePolicy(&st, p, err)
		}
		if err := m.scheduleExpiry(p); err != nil {
			return m.retirePolicy(&st, p, fmt.Errorf("schedule automatic expiry: %w", err))
		}
		return nil
	})
}

func (m *Manager) Release(id, vmID, instanceID string) error {
	if !policyIDPattern.MatchString(id) || vmID == "" {
		return errors.New("invalid connection-limit release identity")
	}
	if _, err := uuid.Parse(instanceID); err != nil {
		return errors.New("invalid Incus instance identity")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.withFileLock(func() error {
		st, err := m.load()
		if err != nil {
			return err
		}
		for _, p := range st.Policies {
			if p.ID != id {
				continue
			}
			if p.VMID != vmID || p.InstanceID != instanceID {
				return errors.New("connection-limit policy target identity mismatch")
			}
			p.RemoveOnly = true
			if err := replacePolicy(&st, p); err != nil {
				return fmt.Errorf("persist pending connection-limit cleanup: %w", err)
			}
			if err := m.save(st); err != nil {
				return fmt.Errorf("persist pending connection-limit cleanup: %w", err)
			}
			if err := m.removeRules(p); err != nil {
				return err
			}
			if err := m.deletePolicy(&st, id); err != nil {
				return err
			}
			m.stopExpiry(id)
			return nil
		}
		return nil // Idempotent release after expiry or a prior successful release.
	})
}

// Expire is called only by the systemd transient timer for this opaque policy ID.
func (m *Manager) Expire(id string) error {
	if !policyIDPattern.MatchString(id) {
		return errors.New("invalid connection-limit policy ID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.withFileLock(func() error {
		st, err := m.load()
		if err != nil {
			return err
		}
		for _, p := range st.Policies {
			if p.ID == id {
				p.RemoveOnly = true
				if err := replacePolicy(&st, p); err != nil {
					return fmt.Errorf("persist pending connection-limit cleanup: %w", err)
				}
				if err := m.save(st); err != nil {
					return fmt.Errorf("persist pending connection-limit cleanup: %w", err)
				}
				if err := m.removeRules(p); err != nil {
					return err
				}
				return m.deletePolicy(&st, id)
			}
		}
		return nil
	})
}

// Reconcile revalidates the Incus identity and addresses after service/host
// restarts. It removes rules tied to an instance that was deleted or recreated,
// and re-applies only still-leased rules for the same managed instance.
func (m *Manager) Reconcile(ctx context.Context, resolve Resolver) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.withFileLock(func() error {
		st, err := m.load()
		if err != nil {
			return err
		}
		var failures []error
		for i := 0; i < len(st.Policies); {
			p := st.Policies[i]
			if p.RemoveOnly || p.ExpiresAt <= time.Now().Unix() {
				if !p.RemoveOnly {
					p.RemoveOnly = true
					if err := replacePolicy(&st, p); err != nil {
						failures = append(failures, err)
						i++
						continue
					}
					if err := m.save(st); err != nil {
						failures = append(failures, fmt.Errorf("persist pending expiry cleanup: %w", err))
						i++
						continue
					}
				}
				if err := m.removeRules(p); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				if err := m.deletePolicy(&st, p.ID); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				m.stopExpiry(p.ID)
				continue
			}
			target, resolveErr := resolve(ctx, p.VMID)
			if resolveErr != nil {
				failures = append(failures, fmt.Errorf("resolve %s: %w", p.VMID, resolveErr))
				i++
				continue
			}
			if !target.Managed || target.InstanceID != p.InstanceID {
				p.RemoveOnly = true
				if err := replacePolicy(&st, p); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				if err := m.save(st); err != nil {
					failures = append(failures, fmt.Errorf("persist pending identity cleanup: %w", err))
					i++
					continue
				}
				if err := m.removeRules(p); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				if err := m.deletePolicy(&st, p.ID); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				m.stopExpiry(p.ID)
				continue
			}
			ips, ipErr := validateIPs(target.IPs)
			if ipErr != nil || !target.Running || len(ips) == 0 {
				if err := m.removeRules(p); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				if len(p.IPs) != 0 {
					p.IPs = nil
					if err := replacePolicy(&st, p); err != nil {
						failures = append(failures, err)
						i++
						continue
					}
					if err := m.save(st); err != nil {
						failures = append(failures, err)
					}
				}
				i++
				continue
			}
			if !sameIPs(p.IPs, ips) {
				if err := m.removeRules(p); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				p.IPs = ips
				if err := replacePolicy(&st, p); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
				if err := m.save(st); err != nil {
					failures = append(failures, err)
					i++
					continue
				}
			}
			if err := m.installRules(p); err != nil {
				failures = append(failures, err)
				i++
				continue
			}
			if err := m.scheduleExpiry(p); err != nil {
				failures = append(failures, m.retirePolicy(&st, p, err))
				continue
			}
			i++
		}
		return errors.Join(failures...)
	})
}

// retirePolicy durably records cleanup intent before touching firewall state.
// If removal fails, Reconcile retries the exact owned rules and never reinstalls
// a policy whose caller was told that activation failed.
func (m *Manager) retirePolicy(st *state, p Policy, cause error) error {
	p.RemoveOnly = true
	if err := replacePolicy(st, p); err != nil {
		return errors.Join(cause, fmt.Errorf("record cleanup intent: %w", err))
	}
	if err := m.save(*st); err != nil {
		return errors.Join(cause, fmt.Errorf("persist cleanup intent: %w", err))
	}
	if err := m.removeRules(p); err != nil {
		return errors.Join(cause, fmt.Errorf("cleanup firewall rules: %w", err))
	}
	if err := m.deletePolicy(st, p.ID); err != nil {
		return errors.Join(cause, fmt.Errorf("persist completed cleanup: %w", err))
	}
	m.stopExpiry(p.ID)
	return cause
}

func (m *Manager) deletePolicy(st *state, id string) error {
	updated := state{Policies: append([]Policy(nil), st.Policies...)}
	updated.Policies = removePolicy(updated.Policies, id)
	if err := m.save(updated); err != nil {
		return err
	}
	*st = updated
	return nil
}

func replacePolicy(st *state, policy Policy) error {
	for i := range st.Policies {
		if st.Policies[i].ID == policy.ID {
			st.Policies[i] = policy
			return nil
		}
	}
	return fmt.Errorf("connection-limit policy %s missing from state", policy.ID)
}

func validatePolicy(p Policy) error {
	if !policyIDPattern.MatchString(p.ID) || p.VMID == "" || len(p.VMID) > 200 || strings.ContainsAny(p.VMID, "\x00\r\n") {
		return errors.New("invalid connection-limit policy target")
	}
	if _, err := uuid.Parse(p.InstanceID); err != nil {
		return errors.New("invalid Incus instance identity")
	}
	if p.Max < 100 || p.Max > 10000 {
		return errors.New("max_connections must be between 100 and 10000")
	}
	now := time.Now().Unix()
	if p.ExpiresAt < now+60 || p.ExpiresAt > now+3600 {
		return errors.New("connection-limit lease must be between 60 and 3600 seconds")
	}
	ips, err := validateIPs(p.IPs)
	if err != nil || len(ips) == 0 {
		return errors.New("at least one valid global Incus address is required")
	}
	return nil
}

func validateIPs(raw []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, value := range raw {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
			return nil, fmt.Errorf("invalid global container address %q", value)
		}
		value = addr.Unmap().String()
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *Manager) installRules(p Policy) error {
	ips, err := validateIPs(p.IPs)
	if err != nil {
		return err
	}
	for _, value := range ips {
		addr, _ := netip.ParseAddr(value)
		tool := "iptables"
		if addr.Is6() {
			tool = "ip6tables"
		}
		if err := m.ensureChain(tool); err != nil {
			return err
		}
		for _, direction := range []string{"in", "out"} {
			args := ruleArgs(p, addr, direction)
			check := append([]string{"-C", chainName}, args...)
			if _, err := m.runTool(tool, check...); err == nil {
				continue
			}
			appendRule := append([]string{"-A", chainName}, args...)
			if out, err := m.runTool(tool, appendRule...); err != nil {
				return commandError(tool, appendRule, out, err)
			}
		}
	}
	return nil
}

func (m *Manager) ensureChain(tool string) error {
	if out, err := m.runTool(tool, "-N", chainName); err != nil {
		if _, checkErr := m.runTool(tool, "-S", chainName); checkErr != nil {
			return commandError(tool, []string{"-N", chainName}, out, err)
		}
	}
	if _, err := m.runTool(tool, "-C", "FORWARD", "-j", chainName); err != nil {
		args := []string{"-I", "FORWARD", "1", "-j", chainName}
		if out, insertErr := m.runTool(tool, args...); insertErr != nil {
			return commandError(tool, args, out, insertErr)
		}
	}
	return nil
}

func (m *Manager) removeRules(p Policy) error {
	var failures []error
	for _, value := range p.IPs {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		tool := "iptables"
		if addr.Is6() {
			tool = "ip6tables"
		}
		for _, direction := range []string{"in", "out"} {
			args := ruleArgs(p, addr, direction)
			if _, err := m.runTool(tool, append([]string{"-C", chainName}, args...)...); err != nil {
				continue
			}
			deleteArgs := append([]string{"-D", chainName}, args...)
			if out, err := m.runTool(tool, deleteArgs...); err != nil {
				failures = append(failures, commandError(tool, deleteArgs, out, err))
			}
		}
	}
	return errors.Join(failures...)
}

func ruleArgs(p Policy, addr netip.Addr, direction string) []string {
	addressFlag, countDirection, label := "-s", "--connlimit-saddr", "out"
	if direction == "in" {
		addressFlag, countDirection, label = "-d", "--connlimit-daddr", "in"
	}
	mask := 32
	if addr.Is6() {
		mask = 128
	}
	comment := "narwhal-climit:" + p.ID + ":" + label
	return []string{
		addressFlag, addr.String(), "-p", "tcp", "--syn",
		"-m", "connlimit", "--connlimit-above", strconv.Itoa(p.Max),
		"--connlimit-mask", strconv.Itoa(mask), countDirection,
		"-m", "comment", "--comment", comment,
		"-j", "REJECT", "--reject-with", "tcp-reset",
	}
}

func (m *Manager) scheduleExpiry(p Policy) error {
	unit := "narwhal-connlimit-expire-" + p.ID
	if _, err := m.run("systemctl", "is-active", "--quiet", unit+".timer"); err == nil {
		return nil
	}
	remaining := p.ExpiresAt - time.Now().Unix()
	if remaining < 1 {
		remaining = 1
	}
	args := []string{
		"--unit=" + unit,
		"--on-active=" + strconv.FormatInt(remaining, 10) + "s",
		"--timer-property=AccuracySec=1s",
		"--collect",
		m.executable,
		"--config", m.configPath,
		"--expire-connlimit", p.ID,
	}
	if out, err := m.run("systemd-run", args...); err != nil {
		return commandError("systemd-run", args, out, err)
	}
	return nil
}

func (m *Manager) stopExpiry(id string) {
	_, _ = m.run("systemctl", "stop", "narwhal-connlimit-expire-"+id+".timer")
}

func (m *Manager) runTool(tool string, args ...string) ([]byte, error) {
	all := append([]string{"-w", "5", "-t", "filter"}, args...)
	return m.run(tool, all...)
}

func (m *Manager) withFileLock(fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(m.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

func (m *Manager) load() (state, error) {
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, nil
	}
	if err != nil {
		return state{}, err
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return state{}, fmt.Errorf("read connection-limit state: %w", err)
	}
	return st, nil
}

func (m *Manager) save(st state) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.path), ".connlimit-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, m.path)
}

func removePolicy(policies []Policy, id string) []Policy {
	out := policies[:0]
	for _, p := range policies {
		if p.ID != id {
			out = append(out, p)
		}
	}
	return out
}

func sameIPs(a, b []string) bool {
	aa, errA := validateIPs(a)
	bb, errB := validateIPs(b)
	if errA != nil || errB != nil || len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func commandError(name string, args []string, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if len(message) > 300 {
		message = message[:300]
	}
	if message != "" {
		return fmt.Errorf("%s %s failed: %s: %w", name, strings.Join(args, " "), message, err)
	}
	return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
}
