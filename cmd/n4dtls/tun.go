// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

package main

// Reinjection primitive A from §2 D2: a TUN device. Writing a full IP packet to the
// TUN fd makes the kernel receive it on the input path of that interface — the original
// L3 header is restored byte-for-byte, no information is lost, and because it never
// traverses the OUTPUT chain our egress NFQUEUE rule cannot recapture it (no loop).
// The only gotcha is rp_filter: the injected packet's source is the PEER NF's address,
// whose route is net1, not the tun, so a strict reverse-path filter would drop it. We
// set rp_filter=0 on the tun (and log it), which is the #1 cause of silently vanishing
// injected packets (§2 D2).

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type tunDev struct {
	f    *os.File
	name string
}

// openTUN creates (or attaches to) a TUN device, brings it up, and disables rp_filter on
// it so peer-sourced injected packets are accepted. IFF_NO_PI: the fd carries raw IP
// packets with no 4-byte packet-info prefix, so a DTLS record's bytes are written verbatim.
func openTUN(name string) (*tunDev, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (need CAP_NET_ADMIN)", err)
	}
	var ifr [40]byte
	copy(ifr[:15], name)
	// flags at offset 16: IFF_TUN | IFF_NO_PI
	const IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
	*(*uint16)(unsafe.Pointer(&ifr[16])) = IFF_TUN | IFF_NO_PI
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF %q: %v", name, e)
	}
	// bring the link up (needed for the kernel to accept injected frames)
	if err := ifUp(name); err != nil {
		f.Close()
		return nil, err
	}
	// rp_filter must be DISABLED for injected packets to be delivered. The injected
	// packet is peer-sourced (its src is the peer NF, whose route is net1, not the tun),
	// so reverse-path filtering drops it. The effective value is max(conf/all, conf/<if>),
	// so setting only the tun's knob is NOT enough when conf/all is strict — and loose
	// mode (2) is also insufficient here because the source belongs to a directly-connected
	// subnet arriving on the "wrong" interface (verified: only 0 delivers). We therefore set
	// conf/all/rp_filter=0 in THIS netns (the NF's own netns) and the tun's, and log both so
	// the setting is on the record (§2 D2 / I8).
	setRP := func(path, v string) {
		if err := os.WriteFile(path, []byte(v), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "n4dtls: WARN could not set %s=%s: %v (injected packets may be rp_filter-dropped)\n", path, v, err)
		} else {
			fmt.Fprintf(os.Stderr, "n4dtls: rp_filter %s=%s\n", path, v)
		}
	}
	setRP("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
	setRP("/proc/sys/net/ipv4/conf/"+name+"/rp_filter", "0")
	return &tunDev{f: f, name: name}, nil
}

// ifUp does the equivalent of `ip link set <name> up` via a netlink-free ioctl.
func ifUp(name string) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket for ifup: %w", err)
	}
	defer unix.Close(s)
	var ifr [40]byte
	copy(ifr[:15], name)
	// read current flags
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(s), unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return fmt.Errorf("SIOCGIFFLAGS %q: %v", name, e)
	}
	flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(s), unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return fmt.Errorf("SIOCSIFFLAGS up %q: %v", name, e)
	}
	return nil
}

// inject writes one whole IP packet onto the input path.
func (t *tunDev) inject(ip []byte) (int, error) { return t.f.Write(ip) }

func (t *tunDev) close() {
	if t != nil && t.f != nil {
		t.f.Close()
	}
}
