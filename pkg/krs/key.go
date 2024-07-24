package krs

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Key permission flags which could be or'ed. The KEY_PERM_ prefix is choosen, that it most probably wont collide, if
// this values are added to the go library.
const (
	KEY_PERM_POS_VIEW    = 0x01000000 /* possessor can view a key's attributes */
	KEY_PERM_POS_READ    = 0x02000000 /* possessor can read key payload / view keyring */
	KEY_PERM_POS_WRITE   = 0x04000000 /* possessor can update key payload / add link to keyring */
	KEY_PERM_POS_SEARCH  = 0x08000000 /* possessor can find a key in search / search a keyring */
	KEY_PERM_POS_LINK    = 0x10000000 /* possessor can create a link to a key/keyring */
	KEY_PERM_POS_SETATTR = 0x20000000 /* possessor can set key attributes */
	KEY_PERM_POS_ALL     = 0x3f000000

	KEY_PERM_USR_VIEW    = 0x00010000 /* user permissions... */
	KEY_PERM_USR_READ    = 0x00020000
	KEY_PERM_USR_WRITE   = 0x00040000
	KEY_PERM_USR_SEARCH  = 0x00080000
	KEY_PERM_USR_LINK    = 0x00100000
	KEY_PERM_USR_SETATTR = 0x00200000
	KEY_PERM_USR_ALL     = 0x003f0000

	KEY_PERM_GRP_VIEW    = 0x00000100 /* group permissions... */
	KEY_PERM_GRP_READ    = 0x00000200
	KEY_PERM_GRP_WRITE   = 0x00000400
	KEY_PERM_GRP_SEARCH  = 0x00000800
	KEY_PERM_GRP_LINK    = 0x00001000
	KEY_PERM_GRP_SETATTR = 0x00002000
	KEY_PERM_GRP_ALL     = 0x00003f00

	KEY_PERM_OTH_VIEW    = 0x00000001 /* third party permissions... */
	KEY_PERM_OTH_READ    = 0x00000002
	KEY_PERM_OTH_WRITE   = 0x00000004
	KEY_PERM_OTH_SEARCH  = 0x00000008
	KEY_PERM_OTH_LINK    = 0x00000010
	KEY_PERM_OTH_SETATTR = 0x00000020
	KEY_PERM_OTH_ALL     = 0x0000003f

	KEY_PERM_UNDEF = 0x00000000
)

// Helper function for Syscall
func callWithInts(command, a1, a2, a3, a4, a5 int) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		uintptr(command),
		uintptr(a1),
		uintptr(a2),
		uintptr(a3),
		uintptr(a4),
		uintptr(a5),
	)
	if errno != 0 {
		var err error = errno
		return err
	}
	return nil
}

type KeyType uint8

// For now only the predefined types are supported.
const (
	TypeInvalid KeyType = iota
	TypeKeyring
	TypeUser
)

func KeyTypeToString(t KeyType) (string, error) {
	if t == TypeKeyring {
		return "keyring", nil
	} else if t == TypeUser {
		return "user", nil

	} else {
		return "", fmt.Errorf("Unsupported key type identifier: %v", t)
	}
}

func StringToKeyType(s string) (KeyType, error) {
	if s == "keyring" {
		return TypeKeyring, nil
	} else if s == "user" {
		return TypeUser, nil
	} else {
		return TypeInvalid, fmt.Errorf("Unsupported key type identifier: %s", s)
	}
}

// Transfer secret key data in a more secure way.
// The data can only read once, by internal methods. Any further atempt will give an error. Package external methods
// have no access to the data.
//
// Create storage for the key data.
//
//	data := make([]byte, 256)
//
// Populate data with the private key data.
// And asign it to a KeyData type.
//
//	k := &KeyData{data: &data}
//
// Use it for transport to the key retention service.
// Overwrite the key data, so it can not leak on program termination.
//
//	r := k.Overwrite()
type KeyData struct {
	data  *[]byte
	valid bool
}

// Create payload data for a key to be used with the Add or Update methods.
func NewKeyData(data *[]byte) *KeyData {
	d := &KeyData{
		data:  data,
		valid: true,
	}
	return d
}

// Overwrites the secure KeyData.
// This method shall be called for every KeyData, if it is not needed anymore.
func (k *KeyData) Overwrite() (byte, error) {
	k.valid = false
	var ret byte = 0
	for i := 0; i < len(*k.data); i++ {
		ret += byte(i & 0xFF)
		(*k.data)[i] = byte(i & 0xFF)
	}
	return ret, nil
}

func (k *KeyData) getData() (*[]byte, error) {
	if !k.valid {
		return nil, errors.New("KeyData is not valid")
	}
	k.valid = false
	return k.data, nil
}

// Add a key to a keyring.
// The ringId could be one of the pre-defined unix.KEY_SPEC_* id's or the id of a decendant keyring.
// If a key or a keyring should be created is specified by the KeyType tp.
// The key's description desc could be empty. But it will be used for searching for a key.
// A payload - data, is only valid for keys. Keyrings store the decendants in the payload area.
// Returns on success the id of the newly created key or keyring.
func Add(ringId int, tp KeyType, desc string, data *KeyData) (int, error) {
	t, err := KeyTypeToString(tp)
	if err != nil {
		err = fmt.Errorf("KeyTypeToString failed: %v", err)
		return -1, err
	}

	var dummy []byte
	d := &dummy
	if data != nil {
		d, err = data.getData()
		if err != nil {
			err = fmt.Errorf("getData failed: %v", err)
			return -1, err
		}
	}
	return unix.AddKey(t, desc, *d, ringId)
}

// Clear out a keyring with ringId, from all decendant keys or keyrings. The calling process must have write permissions
// to the keyring, else an error will be returned. Calling this method on something else than a keyring is an error.
func Clear(ringId int) error {
	return callWithInts(unix.KEYCTL_CLEAR, ringId, 0, 0, 0, 0)
}

// A Description of a key or keyring, as returned by the Describe method.
type Description struct {
	Type KeyType // TypeKey or TypeKeyring
	UID  int     // User id
	GID  int     // Group id
	Perm uint32  // Access permissions
	Desc string  // The description of the key or keyring, as set bey Add.
}

// Get a summary of key attributes.
func Describe(id int) (*Description, error) {
	str, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, id)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(str, ";")
	tp, err := StringToKeyType(parts[0])
	if err != nil {
		return nil, err
	}
	uid, _ := strconv.Atoi(parts[1])
	gid, _ := strconv.Atoi(parts[2])
	perm, _ := strconv.ParseUint(parts[3], 16, 32)
	return &Description{
		Type: tp,
		UID:  uid,
		GID:  gid,
		Perm: uint32(perm),
		Desc: parts[4],
	}, nil
}

type dhParam struct {
	priv  int32
	prime int32
	base  int32
}

func DHCompute(params DHParameters) ([]byte, error) {
	buffer := make([]byte, uint16(params.Size))

	p := dhParam{
		priv:  int32(params.PrivateKeyId),
		prime: int32(params.PrimeId),
		base:  int32(params.BaseId),
	}

	_, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_DH_COMPUTE,
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0, 0)

	if errno != 0 {
		var err error = errno
		return nil, err
	}

	return buffer, nil
}

// Invalidate a key.
// Marks a key as invalidated, and wakes up the garbage collector. The garbage collector immediately removes the key for
// keyrings and deletes it, when it's reference count reaches zero.
func Invalidate(id int) error {
	return callWithInts(unix.KEYCTL_INVALIDATE, id, 0, 0, 0, 0)
}

func Link(id, ringId int) error {
	return callWithInts(unix.KEYCTL_LINK, id, ringId, 0, 0, 0)
}

// Read the payload from a key / keyring.
// If id refers to a keyring, the payload will contain the id's from the child keys or keyrings.
func Read(id int) ([]int, error) {
	buffer := make([]int, 16)

	r0, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_READ,
		uintptr(id),                         // Key / keyring id.
		uintptr(unsafe.Pointer(&buffer[0])), // Address of the buffer.
		uintptr(64),                         // Size of the buffer in char / bytes.
		0,
		0,
	)

	if errno != 0 {
		if int(r0) > 64 { // buffer to small
			slices.Grow(buffer, (int(r0)-64)/4)
			_, _, errno := unix.Syscall6(
				unix.SYS_KEYCTL,
				unix.KEYCTL_READ,
				uintptr(id),
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(r0),
				0,
				0)
			if errno != 0 {
				var err error = errno
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("Invalid buffer size %d", int(r0))
		}
	}

	return buffer[:(int(r0) / 4)], nil
}

func Revoke(id int) error {
	return callWithInts(unix.KEYCTL_REVOKE, id, 0, 0, 0, 0)
}

// Searches for a key or a keyring
// Searches for a key of type keyType and a description desc, in the keyring with id ringId.If the requested key is
// found, the id of it will be returned, else it returnes -1. Also if the key is found and destRingId is not zero, the
// key will be linked to destRingId. If destRingId is not a keyring or permissions preventing linking, an error will be
// returned.
func Search(ringId int, keyType KeyType, desc string, destRingId int) (int, error) {
	k, err := KeyTypeToString(keyType)
	if err != nil {
		return -1, err
	}
	return unix.KeyctlSearch(ringId, k, desc, destRingId)
}

// Set access permissions to a key or keyring.
// The permission is a bit field, build up from the KEY_PERM_* constants. Setting a bit, wich is not covered by these
// constants, is an error. Also the caller has to have the permissions to change the permission settings.
func SetPermission(id int, perm uint32) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_SETPERM,
		uintptr(id),
		uintptr(perm),
		0, 0, 0,
	)
	if errno != 0 {
		var err error = errno
		return err
	}
	return nil
}

// Set a timeout on a key.
// The timeout could be a number of seconds in the future, as a expiry time for the key. If the timeout is set to 0, the
// internal timeout will be cleared.
func SetTimeout(id int, timeout uint) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_SET_TIMEOUT,
		uintptr(id),
		uintptr(timeout),
		0, 0, 0,
	)
	if errno != 0 {
		var err error = errno
		return err
	}
	return nil
}

// Update the payload on a key.
// For key with id the payload data will be set. It is an error, if id points to a keyring or the caller does not have
// the permissions to modify the payload data.
func Update(id int, data *KeyData) error {
	d, err := data.getData()
	if err != nil {
		fmt.Println("getData failed")
		return err
	}

	_, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_UPDATE,
		uintptr(id),
		uintptr(unsafe.Pointer(&d)),
		uintptr(len(*d)),
		0, 0,
	)
	if errno != 0 {
		var err error = errno
		return err
	}
	return nil
}

// Unlink a key or keyring.
// The key or keyring with id, will be unlinked from the keyring with ringId.
func Unlink(id, ringId int) error {
	return callWithInts(unix.KEYCTL_UNLINK, id, ringId, 0, 0, 0)
}
