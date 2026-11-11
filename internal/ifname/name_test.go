package ifname

import "testing"

func TestResolve(t *testing.T) {
	cases := []struct{ id, name, override, want string }{
		{"net-a", "production", "", "pm-production"}, {"net-a", "hello world", "", "pm-hello-world"}, {"net-a", "  DEV---test!! ", "", "pm-dev-test"}, {"net-a", "é🐱", "", ""}, {"net-a", "abcdefghijklmnop", "", ""}, {"net-a", "prod", "wg-prod", "wg-prod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.id, tc.name, tc.override)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
			if err := Validate(got); err != nil {
				t.Fatal(err)
			}
			again, _ := Resolve(tc.id, tc.name, tc.override)
			if got != again {
				t.Fatal("unstable")
			}
		})
	}
	a, _ := Resolve("net-a", "abcdefghijklmnop", "")
	b, _ := Resolve("net-b", "abcdefghijklmnop", "")
	if a == b {
		t.Fatal("long name collision")
	}
	for _, name := range []string{"", ".", "..", "1234567890123456", "foo/bar", "foo:bar", "foo bar", "élan"} {
		if Validate(name) == nil {
			t.Fatalf("accepted unsafe %q", name)
		}
	}
}
func TestOwnership(t *testing.T) {
	owners := map[string]string{"wg-a": "a", "wg-b": "b", "unmanaged": ""}
	if CheckOwnership("wg-a", "a", owners) != nil {
		t.Fatal("own interface rejected")
	}
	if CheckOwnership("wg-b", "a", owners) == nil || CheckOwnership("unmanaged", "a", owners) == nil {
		t.Fatal("takeover permitted")
	}
}
