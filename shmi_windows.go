package shm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"syscall"
	"unsafe"
)

const (
	NEW_SE_PRIVILEGE_ENABLED uint32 = 0x00000002
	CREATE_GLOBAL_PRIV       string = "SeCreateGlobalPrivilege"
)

var (
	kernel32                  = syscall.MustLoadDLL("kernel32.dll")
	procOpenMappingOfFile     = kernel32.MustFindProc("OpenFileMappingW")
	advapi32                  = syscall.MustLoadDLL("Advapi32.dll")
	procLookupPrivilegeValueW = advapi32.MustFindProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.MustFindProc("AdjustTokenPrivileges")
)

func LookupPrivilegeValue_func(systemName string, name string, luid *int64) error {
	var _p0 *uint16
	var _p1 *uint16
	var err error
	var _r1 uintptr
	var _e1 syscall.Errno
	_p0, err = syscall.UTF16PtrFromString(systemName)
	if err != nil {
		return err
	}
	_p1, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	_r1, _, _e1 = syscall.Syscall(procLookupPrivilegeValueW.Addr(), 3, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(unsafe.Pointer(luid)))
	if _r1 == 0 {
		if _e1 != 0 {
			err = error(_e1)
		} else {
			err = syscall.EINVAL
		}
		return err
	}
	return nil
}

func AdjustTokenPrivilege_func(token windows.Token, input *byte, outputSize uint32, output *byte, requiredsize *uint32) error {
	var _r0 uintptr
	var _e1 syscall.Errno
	var err error = nil
	_r0, _, _e1 = syscall.Syscall6(procAdjustTokenPrivileges.Addr(), 6, uintptr(token), uintptr(0), uintptr(unsafe.Pointer(input)), uintptr(outputSize), uintptr(unsafe.Pointer(output)), uintptr(unsafe.Pointer(requiredsize)))
	if _r0 == 0 {
		if _e1 != 0 {
			err = error(_e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return err
}

func SetTokenPrivilege_func(token windows.Token, sysname string, name string, enabled bool) error {
	var err error
	var val int64
	var b bytes.Buffer
	err = LookupPrivilegeValue_func(sysname, name, &val)
	if err != nil {
		return err
	}
	binary.Write(&b, binary.LittleEndian, uint32(1))
	binary.Write(&b, binary.LittleEndian, val)
	if enabled {
		binary.Write(&b, binary.LittleEndian, uint32(NEW_SE_PRIVILEGE_ENABLED))
	} else {
		binary.Write(&b, binary.LittleEndian, uint32(0))
	}

	err = AdjustTokenPrivilege_func(token, &b.Bytes()[0], uint32(b.Len()), nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func SetPrivilege_func(name string, enabled bool) error {
	var token windows.Token
	var h windows.Handle
	var err error
	h, err = windows.GetCurrentProcess()
	if err != nil {
		err = fmt.Errorf("GetCurrentProcess error[%s]", err.Error())
		return err
	}

	err = windows.OpenProcessToken(h, syscall.TOKEN_QUERY|syscall.TOKEN_ADJUST_PRIVILEGES, &token)
	if err != nil {
		err = fmt.Errorf("OpenProcessToken error[%s]", err.Error())
		return err
	}
	defer token.Close()
	err = SetTokenPrivilege_func(token, "", name, enabled)
	if err != nil {
		if enabled {
			err = fmt.Errorf("enable [%s] error [%s]", name, err.Error())
		} else {
			err = fmt.Errorf("disable [%s] error [%s]", name, err.Error())
		}
		return err
	}
	return nil
}

type shmi struct {
	h    syscall.Handle
	v    uintptr
	size int32
}

// create shared memory. return shmi object.
func create(name string, size int32, global bool) (*shmi, error) {
	var tname string
	var enabled bool = false
	var err error
	if global {
		tname = fmt.Sprintf("Global\\%s", name)
	} else {
		tname = fmt.Sprintf("Local\\%s", name)
	}

	if global {
		err = SetPrivilege_func(CREATE_GLOBAL_PRIV, true)
		if err != nil {
			return nil, err
		}
		enabled = true
		defer func() {
			if enabled {
				SetPrivilege_func(CREATE_GLOBAL_PRIV, false)
			}
		}()
	}

	key, err := syscall.UTF16PtrFromString(tname)
	if err != nil {
		return nil, err
	}

	h, err := syscall.CreateFileMapping(
		syscall.InvalidHandle, nil,
		syscall.PAGE_READWRITE, 0, uint32(size), key)
	if err != nil {
		return nil, os.NewSyscallError("CreateFileMapping", err)
	}

	v, err := syscall.MapViewOfFile(h, syscall.FILE_MAP_WRITE|syscall.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		syscall.CloseHandle(h)
		return nil, os.NewSyscallError("MapViewOfFile", err)
	}

	return &shmi{h, v, size}, nil
}

// open shared memory. return shmi object.
func open(name string, size int32, global bool) (*shmi, error) {
	var _p0 *uint16
	var err error
	var _e1 syscall.Errno
	var _r0 uintptr
	var h syscall.Handle
	var v uintptr
	var tname string
	var enabled bool = false
	if global {
		tname = fmt.Sprintf("Global\\%s", name)
		err = SetPrivilege_func(CREATE_GLOBAL_PRIV, true)
		if err != nil {
			return nil, err
		}
		enabled = true
		defer func() {
			if enabled {
				SetPrivilege_func(CREATE_GLOBAL_PRIV, false)
			}
			enabled = false
		}()
	} else {
		tname = fmt.Sprintf("Local\\%s", name)
	}

	_p0, err = syscall.UTF16PtrFromString(tname)
	if err != nil {
		return nil, err
	}
	err = nil
	_r0, _, _e1 = syscall.Syscall(procOpenMappingOfFile.Addr(), 3, uintptr(syscall.FILE_MAP_WRITE), uintptr(0), uintptr(unsafe.Pointer(_p0)))
	if _r0 == 0 {
		if _e1 != 0 {
			err = error(_e1)
		} else {
			err = syscall.EINVAL
		}
		return nil, err
	}
	h = syscall.Handle(_r0)
	v, err = syscall.MapViewOfFile(h, syscall.FILE_MAP_WRITE|syscall.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		syscall.CloseHandle(h)
		return nil, err
	}
	return &shmi{h, v, size}, nil
}

func (o *shmi) close() error {
	if o.v != uintptr(0) {
		syscall.UnmapViewOfFile(o.v)
		o.v = uintptr(0)
	}
	if o.h != syscall.InvalidHandle {
		syscall.CloseHandle(o.h)
		o.h = syscall.InvalidHandle
	}
	return nil
}

// read shared memory. return read size.
func (o *shmi) readAt(p []byte, off int64) (n int, err error) {
	if off >= int64(o.size) {
		return 0, io.EOF
	}
	if max := int64(o.size) - off; int64(len(p)) > max {
		p = p[:max]
	}
	return copyPtr2Slice(o.v, p, off, o.size), nil
}

// write shared memory. return write size.
func (o *shmi) writeAt(p []byte, off int64) (n int, err error) {
	if off >= int64(o.size) {
		return 0, io.EOF
	}
	if max := int64(o.size) - off; int64(len(p)) > max {
		p = p[:max]
	}
	return copySlice2Ptr(p, o.v, off, o.size), nil
}
