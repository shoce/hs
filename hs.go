/*
Hs

history:
2020/6/5 v1
2020/10/16 repl
20/302 2020/10/28 stdin reading support
20/302 interrupt signal (ctrl+c) catching so only child processes get it
still not working with root sessions:
Oct 28 21:37:28 ci sshd[3685911]: error: session_signal_req: session signalling requires privilege separation


GoFmt GoBuildNull GoBuild GoRelease GoRun

Variables:
Host variable checked before every command execution: if it is empty then run locally; otherwise run via ssh.
User variable stores user name if run via ssh.
Dir variable stores the current working directory.
Status variable tells exit status of the last command executed.

Reserved words:
ls, ll [path] / list directory of file by path
cd [dir] / change $dir
if X { one } else { two } / branch execution
for x, y := / loop
! / negate $status
~ regexp string / match string against regexp
exit [status] / exit shell with status

*/

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

var (
	Version string

	Proxy       string // proxy chain separated by semicolons
	ProxyChain  = []string{}
	ProxyDialer proxy.Dialer
	ProxyConn   net.Conn

	Hostname string
	Host     string // host network address to run commands on: empty or localhost to run with exec() and hostname[:port] to use ssh transport

	SshClientConfig *ssh.ClientConfig
	SshConn         *ssh.Conn
	SshClient       *ssh.Client

	User string // user name

	UserPassword   string
	UserKeyFile    string
	UserKey        string
	UserSigner     ssh.Signer
	UserAuthMethod ssh.AuthMethod

	Dir string // current directory
	Wd  string

	Status string // status of the last run command

	InterruptChan chan bool
)

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
	const Beat = time.Duration(24) * time.Hour / 1000
	tzBiel := time.FixedZone("Biel", 60*60)
	t := time.Now().In(tzBiel)
	ty := t.Sub(time.Date(t.Year(), 1, 1, 0, 0, 0, 0, tzBiel))
	td := t.Sub(time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, tzBiel))
	ts := fmt.Sprintf(
		"%d/%d@%d",
		t.Year()%1000,
		int(ty/(time.Duration(24)*time.Hour))+1,
		int(td/Beat),
	)
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, ts+" "+msg+"\n")
	} else {
		fmt.Fprintf(os.Stderr, ts+" "+msg+"\n", args...)
	}
}

func logstatus() {
	if Host == "" {
		var err error
		Dir, err = os.Getwd()
		if err != nil {
			log("os.Getwd: %v", err)
		}
	}
	lognl()
	log(underline("Status=%s Hostname=%s Host=%s User=%s Dir=%s hs ; "), Status, Hostname, Host, User, Dir)
}

func init() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(Version)
		os.Exit(0)
	}

	var err error

	Proxy = os.Getenv("Proxy")
	//log("Proxy:%s", Proxy)
	ProxyChain = strings.FieldsFunc(Proxy, func(c rune) bool { return c == ';' })
	//log("ProxyChain:(%d)%v", len(ProxyChain), ProxyChain)
	ProxyDialer = proxy.Direct

	Host = os.Getenv("Host")
	//log("Host:%s", Host)

	User = os.Getenv("User")
	//log("User:%s", User)

	UserPassword = os.Getenv("UserPassword")
	if UserPassword != "" {
		UserAuthMethod = ssh.Password(UserPassword)
	}
	//log("UserPassword:%s", UserPassword)

	UserKeyFile = os.Getenv("UserKeyFile")
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
	//log("UserKey:%s", UserKey)

	SshClientConfig = &ssh.ClientConfig{
		User:            User,
		Auth:            []ssh.AuthMethod{UserAuthMethod},
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	log(fmt.Sprintf("%s: ", cmds))

	copyoutnotify := make(chan error)
	go copynotify(os.Stdout, stdoutpipe, copyoutnotify)
	copyerrnotify := make(chan error)
	go copynotify(os.Stderr, stderrpipe, copyerrnotify)

	err = session.Start(cmds)

	if err != nil {
		log("Start: %v", err)
		return "", err
	}

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

	log(fmt.Sprintf("%s: ", cmds))

	err = command.Start()
	if err != nil {
		return "", fmt.Errorf("Start: %v", err)
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

func main() {
	var err error

	signalchan := make(chan os.Signal, 1)
	signal.Notify(signalchan, os.Interrupt)
	go func() {
		for {
			s := <-signalchan
			switch s {
			case os.Interrupt:
				lognl()
				log("interrupt signal")
				if InterruptChan != nil {
					InterruptChan <- true
				}
			}
		}
	}()

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

		Wd, err = os.Getwd()
		if err != nil {
			log("Getwd: %v", err)
			os.Exit(1)
		}
		//log("Wd:%s", Wd)

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

	inreader := bufio.NewReader(os.Stdin)

	if len(os.Args) > 1 {
		cmd := os.Args[1:]
		cmds := strings.Join(cmd, " ")

		if cmd[len(cmd)-1] == "<" {
			cmd = cmd[:len(cmd)-1]
			cmds = cmds[:len(cmds)-2]
			log("%s stdin: ", cmds)
		}

		Status, _ = run(cmds, cmd, inreader)
		log("%s status: %s", cmds, Status)
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
			cmds = cmds[:len(cmds)-2]
			log("%s stdin: ", cmds)
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
