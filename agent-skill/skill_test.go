package agentskill

import (
	"archive/zip"
	"bytes"
	"sort"
	"strings"
	"testing"
)

// Hermes skips a skill whose frontmatter name differs from its folder; both runtimes need a description.
func TestFrontmatterNamesTheFolder(t *testing.T) {
	md, err := files.ReadFile("kymessages/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	head, _, ok := strings.Cut(strings.TrimPrefix(string(md), "---\n"), "\n---\n")
	if !strings.HasPrefix(string(md), "---\n") || !ok {
		t.Fatal("no frontmatter")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(line, ": ")
		fields[k] = v
	}
	if fields["name"] != "kymessages" || len(fields["description"]) < 40 || len(fields["description"]) > 1024 {
		t.Fatalf("frontmatter %q", fields)
	}
}

func TestConfigFillsEveryPlaceholder(t *testing.T) {
	v := Values{ServerURL: "https://chat.example.com", AccessToken: "kybot_abc123", Owner: "alice"}
	for _, rt := range Runtimes {
		got, err := Config(rt, v)
		if err != nil {
			t.Fatal(rt, err)
		}
		for _, want := range []string{v.ServerURL, v.AccessToken, v.Owner} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: missing %q in\n%s", rt, want, got)
			}
		}
		if strings.Contains(got, "<") || strings.Contains(got, "```") {
			t.Errorf("%s: unfilled or unterminated block:\n%s", rt, got)
		}
	}
}

// Each runtime restricts replies to the owner only.
func TestConfigRequiresOwnerOnly(t *testing.T) {
	v := Values{ServerURL: "https://chat.example", AccessToken: "kybot_t", Owner: "alice"}
	want := map[string][]string{
		"openclaw": {`serverUrl: "https://chat.example"`, `allowFrom: ["alice"]`, `groupAllowFrom: ["alice"]`, `groupPolicy: "allowlist"`},
		"hermes":   {"KYMESSAGES_SERVER_URL=https://chat.example\n", "KYMESSAGES_ACCESS_TOKEN=kybot_t\n", "KYMESSAGES_ALLOWED_USERS=alice\n"},
	}
	for rt, needles := range want {
		got, err := Config(rt, v)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range needles {
			if !strings.Contains(got, n) {
				t.Errorf("%s: missing %q", rt, n)
			}
		}
	}
}

func TestConfigRefusesInjection(t *testing.T) {
	for _, bad := range []string{"", `x"y`, "x\ny", "x y", "x#y", "x\\y", "$(id)"} {
		if _, err := Config("hermes", Values{ServerURL: "https://chat.example", AccessToken: bad, Owner: "alice"}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := Config("../SKILL", Values{}); err == nil {
		t.Error("accepted an unknown runtime")
	}
}

func TestZipHoldsTheSkillFolder(t *testing.T) {
	data, err := Zip()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	want := "kymessages/SKILL.md kymessages/references/hermes.md kymessages/references/openclaw.md kymessages/scripts/kybot.py kymessages/scripts/requirements.txt"
	if strings.Join(names, " ") != want {
		t.Fatalf("zip has %v", names)
	}
}
