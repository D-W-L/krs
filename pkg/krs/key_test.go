package krs

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Start up and clean up is always done by the keyctl comand line interface. Else we would expect, that the self written
// code for this task is valid.

// Helper to create a new key
func newKey(t *testing.T, kt KeyType, ringId int) (int, error) {
	// Create the key
	ns := time.Now().Nanosecond()
	keyName := fmt.Sprintf("KRS-Test-%d", ns)
	typeStr, _ := KeyTypeToString(kt)
	ringIdStr := fmt.Sprintf("%d", ringId)
	payload := ""
	if kt == TypeUser {
		payload = "1234"
	} else {
		payload = ""
	}
	cmd := exec.Command("keyctl", "add", typeStr, keyName, payload, ringIdStr)
	err := cmd.Run()
	if err != nil {
		t.Logf("newKey failed, error: %v", err)
		return -1, err
	}
	// Find the keys ID
	out, err := exec.Command("keyctl", "request", typeStr, keyName).Output()
	if err != nil {
		t.Logf("newKey failed, error: %v", err)
		return -1, err
	}
	i, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return i, nil
}

// Helper to delete a key
func deleteKey(t *testing.T, id int) error {
	keyName := fmt.Sprintf("%d", id)
	cmd := exec.Command("keyctl", "revoke", keyName)
	err := cmd.Run()
	if err != nil {
		t.Logf("deleteKey,  error: %v", err)
		return err
	}
	return nil
}

func getDescription(t *testing.T, id int) (string, error) {
	keyName := fmt.Sprintf("%d", id)
	out, err := exec.Command("keyctl", "describe", keyName).Output()
	if err != nil {
		t.Logf("getDescription,  error: %v", err)
		return "", err
	}

	fields := strings.Fields(string(out))
	return fields[len(fields)-1], nil
}

// Helper to get key permissions
func getPermissions(t *testing.T, id int) (uint32, error) {
	keyName := fmt.Sprintf("%d", id)
	out, err := exec.Command("keyctl", "describe", keyName).Output()
	if err != nil {
		t.Logf("getPermissions,  error: %v", err)
		return 0, err
	}

	perm := strings.Fields(string(out))[1]
	if len(perm) != 24 {
		t.Logf("getPermissions, invalid permissions length %d, expect 24", len(perm))
		return 0, errors.New("Invalid permissions length")
	}

	var ret uint32 = 0
	var n uint32 = 1
	for i := 23; i >= 0; i-- {
		if perm[i] != '-' {
			ret |= n
		}
		n <<= 1
		if i > 0 && i%6 == 0 {
			n <<= 2
		}
	}

	return ret, nil
}

// Helper to set key permissions
func setPermissions(t *testing.T, id int, perm uint32) error {
	keyStr := fmt.Sprintf("%d", id)
	permStr := fmt.Sprintf("%d", perm)
	cmd := exec.Command("keyctl", "setperm", keyStr, permStr)
	err := cmd.Run()
	if err != nil {
		t.Logf("setPermissions,  error: %v", err)
		return err
	}
	return nil
}

func TestGetPermissions(t *testing.T) {
	// Start up, create the key
	id, err := newKey(t, TypeUser, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		t.Fatalf("TestgetPermissions01, start up returned error: %v", err)
	}

	var perm uint32 = 0x3F211705
	err = setPermissions(t, id, perm)
	newPerm, err := getPermissions(t, id)
	deleteKey(t, id)

	if err != nil {
		t.Fatalf("TestGetPermissions01, getPermissions returned error: %v", err)
	}

	if perm != newPerm {
		t.Fatalf("TestGetPermissions01, got %d, expected %d", newPerm, perm)
	}
}

func TestAdd01(t *testing.T) {
	// Test case
	data := []byte{1, 2, 3, 4}
	kd := NewKeyData(&data)
	keyName := fmt.Sprintf("KRS-Test-%d", time.Now().Nanosecond())
	id, err := Add(unix.KEY_SPEC_SESSION_KEYRING, TypeUser, keyName, kd)
	if err != nil {
		t.Fatalf("TestAdd01, Add returned error: %v", err)
	}

	// Clean up, revoke the key
	deleteKey(t, id)
}

func TestSetPermission01(t *testing.T) {
	// Start up, create the key
	id, err := newKey(t, TypeUser, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		t.Fatalf("TestSetPermission01, start up returned error: %v", err)
		return
	}

	// Test case
	var perm uint32 = 0x3F211705
	err = SetPermission(id, perm)
	if err != nil {
		deleteKey(t, id)
		t.Fatalf("TestSetPermission01, SetPermission returned error: %v", err)
	}
	newPerm, err := getPermissions(t, id)
	// clean up
	deleteKey(t, id)

	if err != nil {
		t.Fatalf("TestSetPermission01, getPermissions returned error: %v", err)
	}
	if perm != newPerm {
		t.Fatalf("TestSetPermission01, got %d, expected %d", newPerm, perm)
	}
}

func TestRevoke01(t *testing.T) {
	// Start up, create the key
	id, err := newKey(t, TypeUser, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		t.Fatalf("TestRevoke01, start up returned error: %v", err)
	}

	// Test case
	err = Revoke(id)
	if err != nil {
		// Clean up in case of failure
		deleteKey(t, id)
		t.Fatalf("TestRevoke01, Revoke returned error: %v", err)
	}
}

func TestSearch01(t *testing.T) {
	// Start up, create a keyring
	ringId, err := newKey(t, TypeKeyring, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		t.Fatalf("TestSearch01, start up returned error: %v", err)
	}
	// Start up, create the key
	id, err := newKey(t, TypeUser, ringId)
	if err != nil {
		deleteKey(t, ringId)
		t.Fatalf("TestSearch01, start up returned error: %v", err)
	}

	desc, err := getDescription(t, id)
	if err != nil {
		// Deleting the keyring, would normaly remove the key as well. But that expects, that the key is attached to the
		// keyring, what may in case of an error be wrong. So do it the safe way and delete it explicitly.
		deleteKey(t, id)
		deleteKey(t, ringId)
		t.Fatalf("TestSearch01, start up returned error: %v", err)
	}

	keyId, err := Search(unix.KEY_SPEC_SESSION_KEYRING, TypeUser, desc, 0)
	deleteKey(t, id)
	deleteKey(t, ringId)
	if err != nil {
		t.Fatalf("TestSearch01, Search returned error: %v", err)
	}
	if keyId != id {
		t.Fatalf("TestSearch01, returned value from Search (%d) is not expected value (%d):", keyId, id)
	}
}

func TestSetTimeout01(t *testing.T) {
	// Start up, create the key
	id, err := newKey(t, TypeUser, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		t.Fatalf("TestSetTimeout01, startup returned error: %v", err)
	}

	// Test case
	err = SetTimeout(id, 2)
	if err != nil {
		t.Fatalf("TestSetTimeout01, SetTimeout returned error: %v", err)
	}

	// Wait untill the kex expired
	good := 0
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second)

		keyName := fmt.Sprintf("%d", id)
		cmd := exec.Command("keyctl", "describe", keyName)
		err := cmd.Run()
		if err != nil {
			break
		}
		good++
	}
	// Key was deleted by timeout
	if good > 0 && good < 6 {
		return
	}

	deleteKey(t, id)
}

func TestUpdate01(t *testing.T) {
	// Start up, create the key
	id, err := newKey(t, TypeUser, unix.KEY_SPEC_SESSION_KEYRING)
	if err != nil {
		t.Fatalf("TestUpdate01, start up returned error: %v", err)
	}

	// Test case
	payload := []byte{1, 2, 3, 4, 5}
	kd := NewKeyData(&payload)
	err = Update(id, kd)
	if err != nil {
		deleteKey(t, id)
		t.Fatalf("TestUpdate01, error: %v", err)
	}

	// Clean up
	deleteKey(t, id)
}
