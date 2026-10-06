package cli

import "testing"

func TestEffectiveMaxPagesFullOverride(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		full       bool
		want       int
	}{
		{name: "profile cap retained by default", configured: 7, want: 7},
		{name: "full ignores configured cap", configured: 7, full: true, want: 0},
		{name: "full remains unbounded when already uncapped", full: true, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveMaxPages(tc.configured, tc.full); got != tc.want {
				t.Errorf("effectiveMaxPages(%d, %t) = %d, want %d", tc.configured, tc.full, got, tc.want)
			}
		})
	}
}
