package model

import "testing"

func TestNormalizeRouteAccountIDsAllowsMoreThanOneThousand(t *testing.T) {
	ids := make([]uint64, 1001)
	for index := range ids {
		ids[index] = uint64(index + 1)
	}

	values, err := normalizeRouteAccountIDs(ids)
	if err != nil {
		t.Fatalf("normalizeRouteAccountIDs() error = %v", err)
	}
	if len(values) != len(ids) {
		t.Fatalf("normalizeRouteAccountIDs() returned %d IDs, want %d", len(values), len(ids))
	}
}
