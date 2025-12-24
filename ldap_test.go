package main

import "testing"

func TestPermissionsFromGroupSuffixes(t *testing.T) {
	tests := []struct {
		name          string
		group         string
		namespace     string
		pullOnly      bool
		deleteAllowed bool
		ok            bool
	}{
		{name: "rwd", group: "team1_rwd", namespace: "team1", pullOnly: false, deleteAllowed: true, ok: true},
		{name: "rw", group: "team2_rw", namespace: "team2", pullOnly: false, deleteAllowed: false, ok: true},
		{name: "rd", group: "team3_rd", namespace: "team3", pullOnly: true, deleteAllowed: true, ok: true},
		{name: "r", group: "team4_r", namespace: "team4", pullOnly: true, deleteAllowed: false, ok: true},
		{name: "bare", group: "team5", namespace: "", pullOnly: false, deleteAllowed: false, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, pullOnly, deleteAllowed, ok := permissionsFromGroup(tt.group)
			if ok != tt.ok {
				t.Fatalf("expected ok %v for group %q, got %v", tt.ok, tt.group, ok)
			}
			if ok {
				if ns != tt.namespace {
					t.Fatalf("expected namespace %q, got %q", tt.namespace, ns)
				}
				if pullOnly != tt.pullOnly {
					t.Fatalf("expected pullOnly %v, got %v", tt.pullOnly, pullOnly)
				}
				if deleteAllowed != tt.deleteAllowed {
					t.Fatalf("expected deleteAllowed %v, got %v", tt.deleteAllowed, deleteAllowed)
				}
			}
		})
	}
}

func TestMorePermissivePullOnly(t *testing.T) {
	tests := []struct {
		name string
		a    User
		b    User
		want bool
	}{
		{
			name: "a write b pull-only",
			a:    User{PullOnly: false, DeleteAllowed: false},
			b:    User{PullOnly: true, DeleteAllowed: false},
			want: true,
		},
		{
			name: "a pull-only b write",
			a:    User{PullOnly: true, DeleteAllowed: false},
			b:    User{PullOnly: false, DeleteAllowed: false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := morePermissive(&tt.a, &tt.b); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
