package krs

import (
	"golang.org/x/sys/unix"
)

// Compute a Diffie-Hellman shared secret or a public key.
// The function parameters are IDs for three keys.
// @param private  The local private key.
// @param prime    The prime p, which is known to both parties.
// @param base     The shared generator or the remote public key.
// If the base is the shared generator, the result is the local public key. If the base is the remote public key, the
// result is the shared secret.
func ComputeDH(private, prime, base int32) ([]byte, error) {
	params := unix.KeyctlDHParams{
		Private: private,
		Prime:   prime,
		Base:    base,
	}

	// This is duplicated code, but saves a copy of "buffer" from a summarizing function.
	size, err := unix.KeyctlDHCompute(&params, nil)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, size)
	_, err = unix.KeyctlDHCompute(&params, buffer)
	return buffer, err
}
