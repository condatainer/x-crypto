package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
)

// Hostbased returns an AuthMethod that performs SSH host-based authentication
// using the system ssh-keysign binary. clientHostKey is the local machine's
// host public key (parsed from /etc/ssh/ssh_host_*_key.pub). sshKeysign is
// the path to the setuid ssh-keysign binary.
//
// ssh-keysign verifies the request by checking that clientHostKey matches one
// of the host keys in /etc/ssh/ssh_host_*_key.pub on the local machine, then
// signs the auth data with the corresponding private key.
func Hostbased(clientHostKey PublicKey, sshKeysign string) AuthMethod {
	return &hostbasedAuth{
		clientHostKey: clientHostKey,
		sshKeysign:    sshKeysign,
	}
}

type hostbasedAuth struct {
	sshKeysign    string
	clientHostKey PublicKey
}

// hbEnvelope is the outer framing used in the ssh-keysign wire protocol:
// ssh_msg_recv reads a 4-byte length prefix then that many bytes.
type hbEnvelope struct {
	Payload []byte
}

// hbSign is the request payload inside the envelope.
type hbSign struct {
	Version uint8  // must be 2
	Fd      uint32 // fd number of the SSH socket in the child process
	Payload []byte // serialised hbSignMessage
}

// hbSigned is the response payload from ssh-keysign.
type hbSigned struct {
	Version uint8  // 2
	Payload []byte // raw signature bytes
}

// hbSignMessage is the data that ssh-keysign signs, encoding the fields
// required by RFC 4252 §9 for host-based authentication.
type hbSignMessage struct {
	Session   []byte
	Msgtype   uint8
	Sshuser   string
	Service   string
	Method    string
	Hostalgo  string
	Blob      []byte
	Localhost string
	Localuser string
}

// hbSignedMessage is the SSH_MSG_USERAUTH_REQUEST body sent to the server.
type hbSignedMessage struct {
	Msgtype   uint8
	Sshuser   string
	Service   string
	Method    string
	Hostalgo  string
	Blob      []byte
	Localhost string
	Localuser string
	Signature []byte
}

func (hb *hostbasedAuth) method() string { return "hostbased" }

func (hb *hostbasedAuth) auth(session []byte, sshuser string, c packetConn, rand io.Reader, _ map[string][]byte) (result authResult, authmethods []string, returnerror error) {
	defer func() {
		if r := recover(); r != nil {
			none := new(noneAuth)
			_, authmethods, _ = none.auth(session, sshuser, c, rand, nil)
			result = authFailure
			returnerror = fmt.Errorf("hostbased auth: %v", r)
		}
	}()

	tr, ok := c.(*handshakeTransport)
	if !ok {
		return authFailure, nil, fmt.Errorf("hostbased: unexpected transport type %T", c)
	}
	innerTr, ok := tr.conn.(*transport)
	if !ok {
		return authFailure, nil, fmt.Errorf("hostbased: unexpected inner transport type %T", tr.conn)
	}

	netConn, ok := innerTr.Closer.(net.Conn)
	if !ok {
		return authFailure, nil, fmt.Errorf("hostbased: underlying closer is not a net.Conn")
	}

	localHost, _, err := net.SplitHostPort(netConn.LocalAddr().String())
	if err != nil {
		return authFailure, nil, fmt.Errorf("hostbased: split local addr: %w", err)
	}

	names, err := net.LookupAddr(localHost)
	if err != nil || len(names) == 0 {
		names = []string{localHost}
	}
	localname := names[0]
	// valid_request in ssh-keysign requires the hostname to end with '.' (FQDN dot).
	// net.LookupAddr adds it for DNS results but not for /etc/hosts entries.
	if !strings.HasSuffix(localname, ".") {
		localname += "."
	}

	u, err := user.Current()
	if err != nil {
		return authFailure, nil, fmt.Errorf("hostbased: get current user: %w", err)
	}

	// Get raw socket fd to pass to ssh-keysign for its security verification.
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := netConn.(syscallConner)
	if !ok {
		return authFailure, nil, fmt.Errorf("hostbased: connection does not support SyscallConn")
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return authFailure, nil, fmt.Errorf("hostbased: SyscallConn: %w", err)
	}

	var rawFd uintptr
	if ctrlErr := rawConn.Control(func(fd uintptr) {
		rawFd = fd
	}); ctrlErr != nil {
		return authFailure, nil, fmt.Errorf("hostbased: control: %w", ctrlErr)
	}

	// Dup so os.NewFile doesn't disrupt the live SSH connection when GC'd.
	dupFd, err := syscall.Dup(int(rawFd))
	if err != nil {
		return authFailure, nil, fmt.Errorf("hostbased: dup socket fd: %w", err)
	}
	socketFile := os.NewFile(uintptr(dupFd), "ssh-conn")
	defer socketFile.Close()

	// ExtraFiles[0] → fd 3 in child (after stdin=0, stdout=1, stderr=2).
	const childSocketFd = 3

	// hostalgo and blob must be the CLIENT's host key — ssh-keysign validates
	// the blob against /etc/ssh/ssh_host_*_key.pub on this machine.
	hostalgo := hb.clientHostKey.Type()
	blob := hb.clientHostKey.Marshal()

	signPayload := Marshal(&hbSignMessage{
		Session:   session,
		Msgtype:   msgUserAuthRequest,
		Sshuser:   sshuser,
		Service:   serviceSSH,
		Method:    hb.method(),
		Hostalgo:  hostalgo,
		Blob:      blob,
		Localhost: localname,
		Localuser: u.Username,
	})

	input := Marshal(&hbEnvelope{
		Payload: Marshal(&hbSign{
			Version: 2,
			Fd:      uint32(childSocketFd),
			Payload: signPayload,
		}),
	})

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(hb.sshKeysign)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{socketFile}

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "(no stderr)"
		}
		return authFailure, nil, fmt.Errorf(
			"hostbased: ssh-keysign failed: %w — %s\n"+
				"  [debug] localname=%q hostalgo=%q sessionLen=%d localuser=%q localHost=%q",
			err, msg, localname, hostalgo, len(session), u.Username, localHost,
		)
	}

	envelope := &hbEnvelope{}
	if err := Unmarshal(stdout.Bytes(), envelope); err != nil {
		return authFailure, nil, fmt.Errorf("hostbased: unmarshal keysign response: %w", err)
	}
	signed := &hbSigned{}
	if err := Unmarshal(envelope.Payload, signed); err != nil {
		return authFailure, nil, fmt.Errorf("hostbased: unmarshal signed: %w", err)
	}
	if signed.Version != 2 {
		return authFailure, nil, fmt.Errorf("hostbased: unexpected keysign response version %d", signed.Version)
	}

	packet := Marshal(&hbSignedMessage{
		Msgtype:   msgUserAuthRequest,
		Sshuser:   sshuser,
		Service:   serviceSSH,
		Method:    hb.method(),
		Hostalgo:  hostalgo,
		Blob:      blob,
		Localhost: localname,
		Localuser: u.Username,
		Signature: signed.Payload,
	})

	if err := c.writePacket(packet); err != nil {
		return authFailure, nil, err
	}

	return handleAuthResponse(c)
}
