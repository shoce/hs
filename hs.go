/*
Hs

history:
020/0605 v1
020/1016 repl
020/302 2020/10/28 stdin reading support
020/302 interrupt signal (ctrl+c) catching so only child processes get it
still not working with root sessions:
Oct 28 21:37:28 ci sshd[3685911]: error: session_signal_req: session signalling requires privilege separation
020/357 UserKeyFile support
021/0502 InReaderBufferSize
021/1117 SILENT
023/0827 VERBOSE
023/0827 keepalive
025/0108 sighup

GoGet
GoFmt
GoBuildNull
GoBuild

GoRun -- put a '<' <readme.text
Kill GoRun

Variables:
Host variable checked before every command execution: if it is empty then run locally; otherwise run via ssh.
User variable stores user name if run via ssh.
Status variable tells exit status of the last command executed.

//
notes for possible future scripting language:
Reserved words:
ls, ll [path] / list directory of file by path
cd [dir] / change $dir
if X { one } else { two } / branch execution
for x, y := / loop
! / negate $status
~ regexp string / match string against regexp
exit [status] / exit shell with status
//

*/

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	NL = "\n"

	InReaderBufferSize = 100 * 1000
)

var (
	Version string

	LogBeatTime bool
	LogUTCTime  bool

	VERBOSE bool
	SILENT  bool

	Proxy       string // proxy chain separated by semicolons
	ProxyChain  = []string{}
	ProxyDialer proxy.Dialer
	ProxyConn   net.Conn

	Hostname string
	Host     string // host network address to run commands on: empty or localhost to run with exec() and hostname[:port] to use ssh transport

	SshKeepAliveInterval time.Duration = 12 * time.Second

	SshClientConfig *ssh.ClientConfig
	SshConn         *ssh.Conn
	SshClient       *ssh.Client

	User string // user name

	UserPassword   string
	UserKeyFile    string
	UserKey        string
	UserSigner     ssh.Signer
	UserAuthMethod ssh.AuthMethod

	Status string // status of the last run command

	InterruptChan chan bool

	TzBiel *time.Location = time.FixedZone("Biel", 60*60)
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Printf("%s\n", Version)
		os.Exit(0)
	}

	if os.Getenv("VERBOSE") != "" {
		VERBOSE = true
	}

	if os.Getenv("SILENT") != "" {
		SILENT = true
	}

	var err error

	Proxy = os.Getenv("Proxy")
	if VERBOSE {
		log("Proxy:%s", Proxy)
	}
	ProxyChain = strings.FieldsFunc(Proxy, func(c rune) bool { return c == ';' })
	if VERBOSE {
		log("ProxyChain:(%d)%v", len(ProxyChain), ProxyChain)
	}
	ProxyDialer = proxy.Direct

	Host = os.Getenv("Host")
	if VERBOSE {
		log("Host:%s", Host)
	}

	User = os.Getenv("User")
	if VERBOSE {
		log("User:%s", User)
	}

	UserPassword = os.Getenv("UserPassword")
	if UserPassword != "" {
		UserAuthMethod = ssh.Password(UserPassword)
	}
	if VERBOSE {
		log("UserPassword:%s", UserPassword)
	}

	if os.Getenv("home") == "" {
		err = os.Setenv("home", os.Getenv("HOME"))
		if err != nil {
			log("Setenv home: %v", err)
		}
	}

	UserKeyFile = os.ExpandEnv(os.Getenv("UserKeyFile"))
	if UserKeyFile != "" {
		userkeybb, err := ioutil.ReadFile(UserKeyFile)
		if err != nil {
			log("Read UserKeyFile: %v", err)
			os.Exit(1)
		}
		UserKey = string(userkeybb)
	}

	if os.Getenv("UserKey") != "" {
		UserKey = os.Getenv("UserKey")
	}

	if UserKey != "" {
		UserSigner, err = ssh.ParsePrivateKey([]byte(UserKey))
		if err != nil {
			log("ParsePrivateKey: %v", err)
			os.Exit(1)
		}
		UserAuthMethod = ssh.PublicKeys(UserSigner)
	}
	if VERBOSE {
		log("UserKey:%s", UserKey)
	}

	if UserAuthMethod == nil {
		log("No user auth method provided: no password and no user key")
		os.Exit(1)
	}

	SshClientConfig = &ssh.ClientConfig{
		User:    User,
		Auth:    []ssh.AuthMethod{UserAuthMethod},
		Timeout: 10 * time.Second,
		//ClientVersion: "hs", // NewClientConn: ssh: handshake failed: ssh: invalid packet length, packet too large
		//HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if VERBOSE {
				log("SSH server public key: type:%s hex:%s", key.Type(), hex.EncodeToString(key.Marshal()))
			}
			return nil
		},
		BannerCallback: func(msg string) error {
			msg = strings.TrimSpace(msg)
			sep := " "
			if strings.Contains(msg, "\n") {
				sep = "\n"
			}
			log("SSH server banner:%s%s", sep, msg)
			return nil
		},
	}
}

func main() {
	var err error

	sigintchan := make(chan os.Signal, 1)
	signal.Notify(sigintchan, syscall.SIGINT)
	go func() {
		for {
			s := <-sigintchan
			switch s {
			case syscall.SIGINT:
				lognl()
				log("interrupt signal")
				if InterruptChan != nil {
					InterruptChan <- true
				}
			}
		}
	}()

	sighupchan := make(chan os.Signal, 1)
	signal.Notify(sighupchan, syscall.SIGHUP)
	go func() {
		for {
			s := <-sighupchan
			switch s {
			case syscall.SIGHUP:
				lognl()
				log("hangup signal")
				os.Exit(2)
			}
		}
	}()

	args := os.Args[1:]

	if Host == "" {

		Hostname, err = os.Hostname()
		if err != nil {
			log("Hostname: %v", err)
			os.Exit(1)
		}
		Hostname = strings.TrimSuffix(Hostname, ".local")
		//log("Hostname:%s", Hostname)

		u, err := user.Current()
		if err != nil {
			log("user.Current: %v", err)
		}
		User = u.Username

	} else {

		if len(ProxyChain) > 0 {
			for _, p := range ProxyChain {
				proxyurl, err := url.Parse(p)
				if err != nil {
					log("Proxy url `%s`: %v", p, err)
					os.Exit(1)
				}
				pd, err := proxy.FromURL(proxyurl, ProxyDialer)
				if err != nil {
					log("Proxy from url: %v", err)
					os.Exit(1)
				}
				ProxyDialer = pd
			}
		}

		if len(strings.Split(Host, ":")) < 2 {
			Host = fmt.Sprintf("%s:22", Host)
			//log("Host:%s", Host)
		}

		err = connectssh()
		if err != nil {
			//log("connect ssh: %v", err)
		}
		if SshClient != nil {
			defer SshClient.Close()
		}
	}

	inreader := bufio.NewReaderSize(os.Stdin, InReaderBufferSize)

	if len(args) > 0 && args[0] != "--" {
		log("the first argument should be `--`, example `hs -- id`")
		os.Exit(1)
	}

	if len(args) > 1 {
		cmd := args[1:]
		cmds := strings.Join(cmd, " ")

		if cmd[len(cmd)-1] == "<" {
			cmd = cmd[:len(cmd)-1]
			cmds = strings.Join(cmd, " ")
			if !SILENT {
				log("%s stdin: ", cmds)
			}
		}

		Status, err = run(cmds, cmd, inreader)
		if err != nil {
			os.Exit(1)
		}
		if Status != "" {
			log("%s status: %s", cmds, Status)
		}
		os.Exit(0)
	}

	var stdinbb []byte
	for {
		logstatus()

		cmds, err := inreader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				log("EOF")
				break
			}
			log("ReadString: %v", err)
			continue
		}

		cmds = strings.TrimSpace(cmds)
		if cmds == "" {
			continue
		}

		cmd := strings.Split(cmds, " ")

		stdinbb = nil
		if cmd[len(cmd)-1] == "<" {
			cmd = cmd[:len(cmd)-1]
			cmds = cmds[:len(cmds)-1]
			if !SILENT {
				log("%s stdin: ", cmds)
			}
			stdinbb, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				log("read stdin: %v", err)
				continue
			}
		}

		Status, err = run(cmds, cmd, bytes.NewBuffer(stdinbb))
		if err != nil {
			continue
		}
	}
}

func lognl() {
	fmt.Fprintf(os.Stderr, "\n")
}

func underline(s string) string {
	if os.Getenv("TERM") != "" {
		return "\033[4m" + s + "\033[0m"
	}
	return s
}

func log(msg string, args ...interface{}) {
	var t time.Time = time.Now()
	var tsuffix string
	var ts string
	if LogBeatTime {
		const BEAT = time.Duration(24) * time.Hour / 1000
		t = t.In(TzBiel)
		ty := t.Sub(time.Date(t.Year(), 1, 1, 0, 0, 0, 0, TzBiel))
		td := t.Sub(time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, TzBiel))
		ts = fmt.Sprintf(
			"%d:"+"%d:"+"%d",
			t.Year()%1000,
			int(ty/(time.Duration(24)*time.Hour))+1,
			int(td/BEAT),
		)
	} else {
		if LogUTCTime {
			t = t.UTC()
			tsuffix = "z"
		} else {
			t = t.Local()
		}
		ts = fmt.Sprintf(
			"%03d:"+"%02d%02d:"+"%02d%02d"+"%s",
			t.Year()%1000,
			t.Month(), t.Day(),
			t.Hour(), t.Minute(),
			tsuffix,
		)
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, ts+" "+msg+NL)
	} else {
		fmt.Fprintf(os.Stderr, ts+" "+msg+NL, args...)
	}
}

func logstatus() {
	lognl()
	log(underline("Status=%s Hostname=%s Host=%s User=%s hs ; "), Status, Hostname, Host, User)
}

func seps(i int, e int) string {
	ee := int(math.Pow(10, float64(e)))
	if i < ee {
		return fmt.Sprintf("%d", i%ee)
	} else {
		f := fmt.Sprintf("0%dd", e)
		return fmt.Sprintf("%s.%"+f, seps(i/ee, e), i%ee)
	}
}

func copynotify(dst io.Writer, src io.Reader, notify chan error) {
	_, err := io.Copy(dst, src)
	if notify != nil {
		notify <- err
	}
}

func connectssh() (err error) {
	ProxyConn, err = ProxyDialer.Dial("tcp", Host)
	if err != nil {
		log("Dial: %v", err)
		return err
	}

	SshConn, SshNewChannelCh, SshRequestCh, err := ssh.NewClientConn(ProxyConn, Host, SshClientConfig)
	if err != nil {
		log("NewClientConn: %v", err)
		return err
	}

	SshClient = ssh.NewClient(SshConn, SshNewChannelCh, SshRequestCh)

	session, err := SshClient.NewSession()
	if err != nil {
		log("NewSession for hostname: %v", err)
		return err
	}
	hostnamebb, err := session.Output("hostname -f")
	if err != nil {
		log("Output for hostname: %v", err)
	}
	Hostname = strings.TrimSpace(string(hostnamebb))

	return nil
}

// https://github.com/golang/go/issues/21478
// https://github.com/golang/go/issues/19338
// https://pkg.go.dev/golang.org/x/crypto/ssh
func keepalive(cl *ssh.Client, conn net.Conn, done <-chan bool) (err error) {
	if VERBOSE {
		log("keepalive start")
	}
	t := time.NewTicker(SshKeepAliveInterval)
	defer t.Stop()
	for {
		/*
			err = conn.SetDeadline(time.Now().Add(2 * SshKeepAliveInterval))
			if err != nil {
				if VERBOSE {
					log("keepalive failed to set deadline: %v", err)
				}
				return fmt.Errorf("failed to set deadline: %w", err)
			}
		*/
		select {
		case <-t.C:
			_, _, err = cl.SendRequest("keepalive@github.com/shoce/hs", true, nil)
			if VERBOSE {
				if err == nil {
					log("keepalive request sent and confirmed")
				} else {
					log("keepalive failed to send request: %v", err)
				}
			}
			if err != nil {
				return fmt.Errorf("failed to send keep alive: %w", err)
			}
		case <-done:
			if VERBOSE {
				log("keepalive done")
			}
			return nil
		}
	}
}

func runssh(cmds string, cmd []string, stdin io.Reader) (status string, err error) {
	if SshClient == nil {
		err = connectssh()
		if err != nil {
			return "", err
		}
	}

	session, err := SshClient.NewSession()
	if err != nil {
		log("NewSession: %v", err)
		log("reconnecting...")
		err = connectssh()
		if err != nil {
			return "", err
		}
		session, err = SshClient.NewSession()
	}
	if err != nil {
		log("NewSession: %v", err)
		return "", err
	}

	/*
		for _, s := range []string{"Dir"} {
			if os.Getenv(s) == "" {
				continue
			}
			if err := session.Setenv(s, os.Getenv(s)); err != nil {
				// ( echo ; echo AcceptEnv Dir ) >>/etc/ssh/sshd_config && systemctl reload sshd
				log("Session.Setenv %s: %v", s, err)
				return "", err
			}
		}
	*/

	/*
		if err := session.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"); err != nil {
			// ( echo ; echo AcceptEnv PATH ) >>/etc/ssh/sshd_config && systemctl reload sshd
			log("Session.Setenv PATH: %v", err)
			return "", err
		}
	*/

	if stdin != nil {
		stdinpipe, err := session.StdinPipe()
		if err != nil {
			return "", fmt.Errorf("stdin pipe for session: %v", err)
		}

		go func() {
			_, err := io.Copy(stdinpipe, stdin)
			if err != nil {
				log("copy to stdin pipe: %v", err)
			}

			err = stdinpipe.Close()
			if err != nil {
				log("close stdin pipe: %v", err)
			}
		}()
	}

	stdoutpipe, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe for session: %v", err)
	}

	stderrpipe, err := session.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("stderr pipe for session: %v", err)
	}

	if !SILENT {
		log(fmt.Sprintf("Host=%s User=%s hs: %s: ", Host, User, cmds))
	}

	copyoutnotify := make(chan error)
	go copynotify(os.Stdout, stdoutpipe, copyoutnotify)
	copyerrnotify := make(chan error)
	go copynotify(os.Stderr, stderrpipe, copyerrnotify)

	err = session.Start(cmds)

	if err != nil {
		log("Start command: %v", err)
		return "", err
	}

	keepalivedonechan := make(chan bool)
	go keepalive(SshClient, ProxyConn, keepalivedonechan)

	InterruptChan = make(chan bool)

	go func() {
		interrupt := <-InterruptChan
		if !interrupt {
			return
		}
		err := session.Signal(ssh.SIGINT)
		if err != nil {
			log("Signal to session: %v", err)
		}
	}()

	err = session.Wait()

	keepalivedonechan <- true
	close(keepalivedonechan)
	keepalivedonechan = nil

	close(InterruptChan)
	InterruptChan = nil

	if err != nil {
		switch err.(type) {
		case *ssh.ExitMissingError:
			status = "missing"
		case *ssh.ExitError:
			exiterr := err.(*ssh.ExitError)
			status = fmt.Sprintf("%d", exiterr.ExitStatus())
			if sig := exiterr.Signal(); sig != "" {
				status += "-" + sig
			}
		default:
			log("Wait: %v", err)
			return "", err
		}
	}

	err = <-copyoutnotify
	if err != nil {
		log(fmt.Sprintf("%s: copy out: %v", cmds, err))
	}

	err = <-copyerrnotify
	if err != nil {
		log(fmt.Sprintf("%s: copy err: %v", cmds, err))
	}

	return status, nil
}

func runlocal(cmds string, cmd []string, stdin io.Reader) (status string, err error) {
	var cmdargs []string
	if len(cmd) > 1 {
		cmdargs = cmd[1:]
	}

	command := exec.Command(cmd[0], cmdargs...)

	var stdinpipe io.WriteCloser
	var stdoutpipe, stderrpipe io.ReadCloser

	if stdin != nil {
		stdinpipe, err = command.StdinPipe()
		if err != nil {
			return "", fmt.Errorf("stdin pipe for command: %v", err)
		}

		go func() {
			_, err := io.Copy(stdinpipe, stdin)
			if err != nil {
				log("write to stdin pipe: %v", err)
			}

			err = stdinpipe.Close()
			if err != nil {
				log("close stdin pipe: %v", err)
			}
		}()
	}

	stdoutpipe, err = command.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("stdout pipe for command: %v", err)
	}
	copyoutnotify := make(chan error)
	go copynotify(os.Stdout, stdoutpipe, copyoutnotify)

	stderrpipe, err = command.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("stderr pipe for command: %v", err)
	}
	copyerrnotify := make(chan error)
	go copynotify(os.Stderr, stderrpipe, copyerrnotify)

	if !SILENT {
		log(fmt.Sprintf("%s: ", cmds))
	}

	err = command.Start()
	if err != nil {
		return "", fmt.Errorf("Start command: %v", err)
	}

	err = command.Wait()

	if err != nil {
		switch err.(type) {
		case *exec.ExitError:
			exiterr := err.(*exec.ExitError)
			status = fmt.Sprintf("%d", exiterr.ExitCode())
		default:
			return "", fmt.Errorf("Wait: %v", err)
		}
	}

	return status, nil
}

func run(cmds string, cmd []string, stdin io.Reader) (status string, err error) {
	if cmds == "" && len(cmd) == 0 {
		return "", errors.New("empty cmd")
	}
	if Host == "" {
		return runlocal(cmds, cmd, stdin)
	} else {
		return runssh(cmds, cmd, stdin)
	}
}

func printpathinfo(fpath string, finfo os.FileInfo, err error) error {
	if err != nil {
		return err
	}

	s := fmt.Sprintf("%s", strings.ReplaceAll(fpath, "\t", "\\\t"))
	if (finfo.Mode() & os.ModeSymlink) != 0 {
		if linkpath, err := os.Readlink(fpath); err != nil {
			return err
		} else {
			s += "@" + linkpath + "@"
		}
	}
	if finfo.IsDir() {
		s += string(os.PathSeparator)
	}

	s += fmt.Sprintf("\tmode:%04o", finfo.Mode()&os.ModePerm)

	if !finfo.IsDir() && (finfo.Mode()&os.ModeSymlink == 0) {
		s += fmt.Sprintf("\tsize:%s", seps(int(finfo.Size()), 3))
	}

	if !finfo.IsDir() && (finfo.Mode()&os.ModeSymlink == 0) {
		f, err := os.Open(fpath)
		if err != nil {
			log("%v", err)
			return err
		}
		defer f.Close()
		fmh, err := mh.SumStream(f, mh.SHA2_256, -1)
		if err != nil {
			log("%v", err)
			return err
		}
		c := cid.NewCidV1(cid.Raw, fmh)
		s += fmt.Sprintf("\tcid:%s", c)
	}
	fmt.Println(s)
	return nil
}

func listpath(fpath string) error {
	if fpath, err := filepath.Abs(fpath); err != nil {
		return err
	} else {
		fpath = filepath.Clean(fpath)
		if err := filepath.Walk(fpath, printpathinfo); err != nil {
			return err
		}
	}
	return nil
}
