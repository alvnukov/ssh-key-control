//go:build darwin && cgo

package agent

/*
#include <launch.h>
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"unsafe"
)

// ActivateSocket receives the launchd-owned listener without rebinding or
// replacing a filesystem socket. FileListener duplicates the descriptor.
func ActivateSocket(name string) (net.Listener, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var fds *C.int
	var count C.size_t
	if code := C.launch_activate_socket(cname, &fds, &count); code != 0 {
		return nil, fmt.Errorf("launch_activate_socket(%q): error %d", name, code)
	}
	defer C.free(unsafe.Pointer(fds))
	if count != 1 {
		for _, fd := range unsafe.Slice(fds, int(count)) {
			C.close(fd)
		}
		return nil, fmt.Errorf("launchd returned %d sockets for %q; expected one", count, name)
	}
	file := os.NewFile(uintptr(*fds), name)
	defer file.Close()
	return net.FileListener(file)
}
