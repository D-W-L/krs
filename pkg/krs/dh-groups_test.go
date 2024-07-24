package krs

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestDHAddPrimeKeys01(t *testing.T) {
	// Test case
	params, err := DHAddPrimeKeys(PrimeSize1536)
	if err != nil {
		t.Fatalf("DHAddPrimeKeys failed, error: %v", err)
	}

	// Verify the built keyring with keys
	ringIdStr := fmt.Sprintf("%d", params.KeyringId)
	out, err := exec.Command("keyctl", "rlist", ringIdStr).Output()
	if err != nil {
		t.Fatalf("DHAddPrimeKeys, keyctl rlist  error: %v", err)
	}

	fields := strings.Fields(string(out))
	if len(fields) != 2 {
		t.Fatalf("DHAddPrimeKeys, number of expected keys is 20, but is %d", len(fields))
	}

	pk, _ := strconv.Atoi(fields[0])
	bk, _ := strconv.Atoi(fields[1])
	if (params.PrimeId != pk || params.BaseId != bk) && (params.PrimeId != bk || params.BaseId != pk) {
		t.Fatal("DHAddPrimeKeys, PrimeId or BaseId is not valid")
	}

	// Clean up
	err = deleteKey(t, params.PrimeId)
	if err != nil {
		t.Fatalf("DHAddPrimeKeys deleteKey failed, error: %v", err)
	}

	err = deleteKey(t, params.BaseId)
	if err != nil {
		t.Fatalf("DHAddPrimeKeys deleteKey failed, error: %v", err)
	}

	err = deleteKey(t, params.KeyringId)
	if err != nil {
		t.Fatalf("DHAddPrimeKeys deleteKey failed, error: %v", err)
	}
}

func TestDHBitsSize01(t *testing.T) {

	lb := len(bits1536) * 8
	if lb != 1536 {
		t.Fatalf("TestDHBitsSize01: expected key size: 1536 is: %d", lb)
	}

	lb = len(bits2048) * 8
	if lb != 2048 {
		t.Fatalf("TestDHBitsSize01: expected key size: 2048 is: %d", lb)
	}

	lb = len(bits3072) * 8
	if lb != 3072 {
		t.Fatalf("TestDHBitsSize01: expected key size: 3072 is: %d", lb)
	}

	lb = len(bits4096) * 8
	if lb != 4096 {
		t.Fatalf("TestDHBitsSize01: expected key size: 4096 is: %d", lb)
	}

	lb = len(bits6144) * 8
	if lb != 6144 {
		t.Fatalf("TestDHBitsSize01: expected key size: 6144 is: %d", lb)
	}

	lb = len(bits8192) * 8
	if lb != 8192 {
		t.Fatalf("TestDHBitsSize01: expected key size: 8192 is: %d", lb)
	}
}
