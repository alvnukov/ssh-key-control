//go:build !darwin || !cgo

package proc

// Without the platform integration nothing can be learned about the caller.
// Every request is then unanchored, which is the same position this program
// was in before process chains existed: signing still works, and a temporary
// decision is still explicit and still expires.
func Resolve(int32, uint32) Chain { return Chain{} }

// ResolveToken has no audit token to read, so it names nobody.
func ResolveToken([]byte) Chain { return Chain{} }

// Alive cannot be answered here, and a decision whose anchor might be gone is
// treated as gone.
func Alive(Link) bool { return false }

// Describe has nothing to add.
func Describe(c Chain) Chain { return c }
