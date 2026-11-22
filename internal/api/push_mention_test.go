package api

import "testing"

func TestBodyHasMention(t *testing.T) {
	for _, c := range []struct {
		body string
		want bool
	}{
		{"@bob", true},
		{"Can you check this, @bob.", true},
		{"ping @bob-", true},
		{"(@bob)", true},
		{"@bob?", true},
		{"@bob.smith is here", false},
		{"@bob-smith", false},
		{"@bobby", false},
		{"mail@bob", false},
		{"é@bob", false},
		{"@bobé", false},
		{"“@bob”", true},
	} {
		if got := bodyHasMention(c.body, "bob"); got != c.want {
			t.Errorf("bodyHasMention(%q, bob) = %v, want %v", c.body, got, c.want)
		}
	}
}
