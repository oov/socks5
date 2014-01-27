package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	verSocks5 = 0x05

	authNoAuthenticationRequired      = 0x00
	authUsernamePassword              = 0x02
	authUsernamePasswordVersion       = 0x01
	authUsernamePasswordStatusSuccess = 0x00
	authUsernamePasswordStatusFailure = 0x01
	authNoAcceptableMethods           = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4Address = 0x01
	atypDomainName  = 0x03
	atypIPv6Address = 0x04

	repSucceeded                     = 0x00
	repGeneralSocksServerFailure     = 0x01
	repConnectionNotAllowedByRuleset = 0x02
	repNetworkUnreachable            = 0x03
	repHostUnreachable               = 0x04
	repConnectionRefused             = 0x05
	repTTLExpired                    = 0x06
	repComandNotSupported            = 0x07
	repAddressTypeNotSupported       = 0x08

	rsvReserved = 0x00
)

var (
	ErrAuthenticationFailed          = errors.New("socks5: authentication failed")
	ErrConnectionNotAllowedByRuleset = errors.New("socks5: connection not allowed by ruleset")
	ErrAddressTypeNotSupported       = errors.New("socks5: address type not supported")
)

type header struct {
	ver     byte
	methods []byte
}

func (h *header) ReadFrom(r io.Reader) (n int64, err error) {
	if err = binary.Read(r, binary.BigEndian, &h.ver); err != nil {
		return
	}
	n++

	if h.ver != verSocks5 {
		err = errors.New("socks5: head.ReadFrom: unsupported protocol version")
		return
	}

	var nm byte
	if err = binary.Read(r, binary.BigEndian, &nm); err != nil {
		return
	}
	n++

	h.methods = make([]byte, nm)
	if _, err = io.ReadFull(r, h.methods); err != nil {
		return
	}
	n += int64(nm)
	return
}

type userpass struct {
	ver    byte
	uname  []byte
	passwd []byte
}

func (up *userpass) ReadFrom(r io.Reader) (n int64, err error) {
	if err = binary.Read(r, binary.BigEndian, &up.ver); err != nil {
		return
	}
	n++

	if up.ver != authUsernamePasswordVersion {
		err = errors.New("socks5: userpass.ReadFrom: unsupported USERNAME/PASSWORD authentication protocol version")
		return
	}

	var ulen, plen byte
	if err = binary.Read(r, binary.BigEndian, &ulen); err != nil {
		return
	}
	n++

	up.uname = make([]byte, ulen)
	if _, err = io.ReadFull(r, up.uname); err != nil {
		return
	}
	n += int64(ulen)

	if err = binary.Read(r, binary.BigEndian, &plen); err != nil {
		return
	}
	n++

	up.passwd = make([]byte, plen)
	if _, err = io.ReadFull(r, up.passwd); err != nil {
		return
	}
	n += int64(plen)
	return
}

type cmd struct {
	ver      byte
	cmd      byte
	rsv      byte
	atyp     byte
	dst_addr []byte
	dst_port uint16
}

func (c *cmd) DestAddress() string {
	var host string
	switch c.atyp {
	case atypIPv4Address:
		host = net.IPv4(c.dst_addr[0], c.dst_addr[1], c.dst_addr[2], c.dst_addr[3]).String()
	case atypDomainName:
		host = string(c.dst_addr)
	case atypIPv6Address:
		host = net.IP(c.dst_addr).String()
	default:
		host = "<unsupported address type>"
	}
	return host + ":" + strconv.Itoa(int(c.dst_port))
}

func (c *cmd) ReadFrom(r io.Reader) (n int64, err error) {
	if err = binary.Read(r, binary.BigEndian, &c.ver); err != nil {
		return
	}
	n++

	if c.ver != verSocks5 {
		err = errors.New("socks5: cmd.ReadFrom: unsupported protocol version")
		return
	}

	if err = binary.Read(r, binary.BigEndian, &c.cmd); err != nil {
		return
	}
	n++

	if err = binary.Read(r, binary.BigEndian, &c.rsv); err != nil {
		return
	}
	n++

	if err = binary.Read(r, binary.BigEndian, &c.atyp); err != nil {
		return
	}
	n++

	var ln byte
	switch c.atyp {
	case atypIPv4Address:
		ln = net.IPv4len
	case atypDomainName:
		if err = binary.Read(r, binary.BigEndian, &ln); err != nil {
			return
		}
		n++
	case atypIPv6Address:
		ln = net.IPv6len
	default:
		err = ErrAddressTypeNotSupported
		return
	}
	c.dst_addr = make([]byte, ln)
	if _, err = io.ReadFull(r, c.dst_addr); err != nil {
		return
	}
	n += int64(ln)

	if err = binary.Read(r, binary.BigEndian, &c.dst_port); err != nil {
		return
	}
	n += 2
	return
}
