package sshproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	PP_SID         = "pp-sid/"
	PP_PRIVATE_KEY = PP_SID + "privateKey"
	ATTESTATION    = "Attestation"
	KUBERNETES     = "Kubernetes"
)

type SshPeer struct {
	sid        string
	phase      string
	terminated string
	sshConn    ssh.Conn
	ctx        context.Context
	done       chan bool
	outbounds  map[string]*Outbound
	inbounds   map[string]*Inbound
	wg         sync.WaitGroup
	upgrade    bool
}

// Inbound side of the Tunnel - incoming tcp connections from local clients
type Inbound struct {
	// tcp peers
	Name        string
	TcpListener *net.TCPListener
	Connections chan *net.Conn
	Phase       string // A - Attestation, K - Kubernetes, B - Both
}

type Outbound struct {
	// tcp peers
	Name    string
	OutAddr string
	Phase   string // A - Attestation, K - Kubernetes, B - Both
}

type Outbounds struct {
	list []*Outbound
}

type Inbounds struct {
	list []*Inbound
}

func (outbounds *Outbounds) Add(tag string) {
	splits := strings.Split(tag, ":")
	var port, host, name, phase string
	if len(splits) == 3 {
		phase = splits[0]
		name = splits[1]
		port = splits[2]
		host = "127.0.0.1"
	} else if len(splits) == 4 {
		phase = splits[0]
		name = splits[1]
		host = splits[2]
		port = splits[3]
	} else {
		log.Fatalf("Outbound Add wrong Tag: %s", tag)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		log.Fatalf("Outbound Add Port '%s' - Err: %v", port, err)
	}
	if phase != "A" && phase != "K" && phase != "B" {
		log.Fatalf("Outbound Add ilegal Phase '%s'", phase)
	}
	outbound := &Outbound{
		Phase:   phase,
		Name:    name,
		OutAddr: host + ":" + port,
	}
	outbounds.list = append(outbounds.list, outbound)
}

func (inbounds *Inbounds) Add(tag string, wg *sync.WaitGroup) (string, string, error) {
	splits := strings.Split(tag, ":")
	if len(splits) != 3 {
		return "", "", fmt.Errorf("Inbound Add wrong Tag: %s", tag)
	}
	phase := splits[0]
	name := splits[1]
	inPort := splits[2]

	if phase != "A" && phase != "K" && phase != "B" {
		log.Fatalf("Inbound Add ilegal Phase '%s'", phase)
	}
	port, err := strconv.ParseUint(inPort, 10, 16)
	if err != nil {
		return "", "", fmt.Errorf("Inbound Add Port '%s' - Err: %v", inPort, err)
	}

	tcpAddr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(port),
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return "", "", fmt.Errorf("Inbound Failed to Listen to Host: %s Port '%s' - Err: %v", name, inPort, err)
	}
	_, p, err := net.SplitHostPort(tcpListener.Addr().String())
	if err != nil {
		panic(err)
	}
	log.Printf("Inboud listening to port %s", p)

	inbound := &Inbound{
		Phase:       phase,
		TcpListener: tcpListener,
		Connections: make(chan *net.Conn),
		Name:        name,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			tcpConn, err := tcpListener.Accept()
			if err != nil {
				//log.Printf("Inbound Accept error: %s - shutdown ssh", err)
				close(inbound.Connections)
				return
			}
			inbound.Connections <- &tcpConn
		}
	}()
	inbounds.list = append(inbounds.list, inbound)
	return name, p, nil
}

// NewInbound create an Inbound and listen to incomming client connections
func (inbounds *Inbounds) DelAll() {
	for _, inbound := range inbounds.list {
		inbound.TcpListener.Close()
	}
	inbounds.list = [](*Inbound){}
}

// NewSshPeer
func NewSshPeer(ctx context.Context, phase string, sshConn ssh.Conn, chans <-chan ssh.NewChannel, sshReqs <-chan *ssh.Request, sid string) *SshPeer {
	peer := &SshPeer{
		sid:       sid,
		phase:     phase,
		sshConn:   sshConn,
		ctx:       ctx,
		done:      make(chan bool, 1),
		outbounds: make(map[string]*Outbound),
		inbounds:  make(map[string]*Inbound),
	}

	if chans == nil || sshReqs == nil {
		log.Panicf("NewSshPeer with illegal parameters chans %v sshReqs %v", chans, sshReqs)
	}

	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		for {
			select {
			// go ssh.DiscardRequests(sshReqs)
			case req := <-sshReqs:
				if req == nil {
					peer.Close("sshReqs closed")
					return
				}
				if req.WantReply {
					if req.Type == "Phase" {
						log.Printf("%s Phase: peer reported Phase %s", phase, string(req.Payload))
						req.Reply(true, []byte(peer.phase))
						continue
					}
					if phase == ATTESTATION && req.Type == "Upgrade" {
						log.Printf("%s Phase: peer reported it is Upgrading to Kubernetes Phase", phase)
						req.Reply(true, []byte(peer.phase))
						peer.upgrade = true
						continue
					}
					req.Reply(false, nil)
				}

			case <-ctx.Done():
				peer.Close("Context Canceled")
				return
			case ch := <-chans:
				if ch == nil {
					peer.Close("chans closed")
					return
				}
				switch ch.ChannelType() {
				default:
					log.Printf("%s Phase: NewSshPeer rejected channel for %s", phase, ch.ChannelType())
					ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", ch.ChannelType()))
				case "tunnel":
					name := string(ch.ExtraData())
					outbound := peer.outbounds[name]
					if outbound == nil || (outbound.Phase == "A" && phase != ATTESTATION) || (outbound.Phase == "K" && phase != KUBERNETES) {
						log.Printf("%s Phase: NewSshPeer rejected tunnel channel: %s", phase, name)
						ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("%s Phase: NewSshPeer rejected tunnel channel  - port not allowed: %s", phase, name))
						continue
					}
					chChan, chReqs, err := ch.Accept()
					if err != nil {
						log.Printf("%s Phase: NewSshPeer failed to accept tunnel channel: %s", phase, err)
						peer.Close("Accept failed")
					}
					log.Printf("%s Phase: NewSshPeer  - peer requested a tunnel channel for %s", phase, name)
					if outbound.Name == "KBS" {
						outbound.acceptProxy(chChan, chReqs, sid, &peer.wg)
					} else {
						outbound.accept(chChan, chReqs, &peer.wg)
					}
				}
			}
		}
	}()
	ok, peerPhase, err := peer.sshConn.SendRequest("Phase", true, []byte(phase))
	if !ok {
		log.Printf("%s Phase: NewSshPeer  - peer did not ok Phase verification", phase)
		peer.Close("Phase verification failed")
		return nil
	}
	if err != nil {
		log.Printf("%s Phase: NewSshPeer  - peer did not ok Phase verification, err: %v", phase, err)
		peer.Close("Phase verification failed")
		return nil
	}
	if string(peerPhase) != phase {
		log.Printf("%s Phase: NewSshPeer  - peer is in a different phase %s", phase, string(peerPhase))
		peer.Close("Phase verification failed")
		return nil
	}
	return peer
}

func (peer *SshPeer) Wait() {
	peer.wg.Wait()
}

func (peer *SshPeer) Close(who string) {
	if peer.terminated == "" {
		//log.Printf("%s Phase: Peer Done by >>> %s <<<", peer.phase, who)
		peer.terminated = who
		peer.sshConn.Close()
		close(peer.done)
	}
}

func (peer *SshPeer) IsUpgraded() bool {
	return peer.upgrade
}

func (peer *SshPeer) Upgrade() {
	ok, _, err := peer.sshConn.SendRequest("Upgrade", true, []byte{})
	if !ok {
		log.Printf("%s Phase: SshPeer Upgrade failed", peer.phase)
		peer.Close("Phase verification failed")
		return
	}
	if err != nil {
		log.Printf("%s Phase:SshPeer Upgrade failed, err: %v", peer.phase, err)
		peer.Close("Phase verification failed")
		return
	}
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) AddInbound(inbound *Inbound) error {
	if (inbound.Phase == "K" && peer.phase == ATTESTATION) || (inbound.Phase == "A" && peer.phase == KUBERNETES) {
		return nil
	}
	log.Printf("%s Phase: AddInbound: %s", peer.phase, inbound.Name)
	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		for {
			select {
			case conn, ok := <-inbound.Connections:
				if !ok {
					//log.Printf("%s Phase: Inbound Listen is done", peer.phase)
					return
				}
				log.Printf("%s Phase: Inbound Accept: %s", peer.phase, inbound.Name)
				NewInboundInstance(*conn, peer, inbound)
			case <-peer.done:
				//log.Printf("%s Phase: Inbound Peer is done", peer.phase)
				return
			}
		}
	}()
	peer.inbounds[inbound.Name] = inbound
	return nil
}

func NewInboundInstance(tcpConn io.ReadWriteCloser, peer *SshPeer, inbound *Inbound) {
	sshChan, channelReqs, err := peer.sshConn.OpenChannel("tunnel", []byte(inbound.Name))
	if err != nil {
		log.Printf("%s Phase: NewInboundInstance OpenChannel %s error: %s", peer.phase, inbound.Name, err)
		return
	}
	log.Printf("%s Phase: NewInboundInstance OpenChannel opening tunnel for: %s", peer.phase, inbound.Name)

	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		for {
			select {
			// go ssh.DiscardRequests(channelReqs)
			case req := <-channelReqs:
				if req == nil {
					//log.Printf("%s Phase: Inbound %s channelReqs closed", peer.phase, inbound.Name)
					peer.Close("channelReqs closed")
					return
				}
				if req.WantReply {
					req.Reply(false, nil)
				}
			case <-peer.done:
				//log.Printf("%s Phase: Inbound %s sshPeer done", peer.phase, inbound.Name)
				tcpConn.Close()
				sshChan.Close()
				return
			}
		}
	}()

	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		_, err = io.Copy(tcpConn, sshChan)
		//log.Printf("%s Phase: Inbound io.Copy from SSH ended on %s", peer.phase, inbound.Name)
		tcpConn.Close()
		sshChan.Close()
	}()

	peer.wg.Add(1)
	go func() {
		defer peer.wg.Done()
		_, err = io.Copy(sshChan, tcpConn)
		//log.Printf("%s Phase: Inbound io.Copy from TCP ended on %s", peer.phase, inbound.Name)
		sshChan.Close()
		tcpConn.Close()
	}()
}

// NewOutbound create an outbound and connect to an outgoing server
func (peer *SshPeer) AddOutbounds(outbounds Outbounds) {
	for _, outbound := range outbounds.list {
		peer.AddOutbound(outbound)

	}
}

// NewOutbound create an outbound and connect to an outgoing server
func (peer *SshPeer) AddInbounds(inbounds Inbounds) error {
	for _, inbound := range inbounds.list {
		err := peer.AddInbound(inbound)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewOutbound create an outbound and connect to an outgoing server
func (peer *SshPeer) AddOutbound(outbound *Outbound) {
	peer.outbounds[outbound.Name] = outbound
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) DelOutbound(outPort string) {
	delete(peer.outbounds, outPort)
}

type SID string

func (sid SID) urlModifier(path string) string {
	if strings.HasSuffix(path, PP_PRIVATE_KEY) {
		return strings.Replace(path, PP_SID, fmt.Sprintf("pp-%s/", sid), 1)
	}
	return path
}

func (outbound *Outbound) acceptProxy(chChan ssh.Channel, chReqs <-chan *ssh.Request, sid string, wg *sync.WaitGroup) {
	remoteUrl, err := url.Parse("http://" + outbound.OutAddr)
	if err != nil {
		log.Printf("Outbound %s acceptProxy error parsing address %s: %v", outbound.Name, outbound.OutAddr, err)
		return
	}

	// The proxy is a Handler - it has a ServeHTTP method
	proxy := httputil.NewSingleHostReverseProxy(remoteUrl)
	proxy.Transport = http.DefaultTransport
	log.Printf("Outbound %s acceptProxy Setting up for sid %s", outbound.Name, sid)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range chReqs {
			if req == nil {
				chChan.Close()
				return
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			recover()
			wg.Done()
		}()
		for {
			bior := bufio.NewReader(chChan)
			if bior == nil {
				log.Printf("Outbound %s acceptProxy nothing to read", outbound.Name)
				chChan.Close()
				return
			}
			req, err := http.ReadRequest(bior)
			if err != nil {
				if err != io.EOF {
					log.Printf("Outbound %s acceptProxy error in proxy ReadRequest: %v", outbound.Name, err)
				}
				chChan.Close()
				return
			}
			req.URL.Path = SID(sid).urlModifier(req.URL.Path)
			req.URL.Scheme = "http"
			req.URL.Host = outbound.OutAddr
			log.Printf("Outbound %s acceptProxy modified URL to %s of host %s", outbound.Name, req.URL.Path, req.URL.Host)

			resp, err := proxy.Transport.RoundTrip(req)
			if err != nil {
				log.Printf("Outbound %s acceptProxy Error in proxy.Transport.RoundTrip: %v", outbound.Name, err)
				chChan.Close()
				return
			}

			if err = resp.Write(chChan); err != nil {
				log.Printf("Outbound %s acceptProxy to %s  Error in proxy resp.Write: %v", outbound.Name, req.URL.Path, err)
			}
			log.Printf("Outbound %s acceptProxy to %s Status Code %d", outbound.Name, req.URL.Path, resp.StatusCode)
		}
	}()
}

func (outbound *Outbound) accept(chChan ssh.Channel, chReqs <-chan *ssh.Request, wg *sync.WaitGroup) {
	tcpConn, err := net.Dial("tcp", outbound.OutAddr)
	if err != nil {
		log.Printf("Outbound %s acept dial address %s err: %s - closing channel", outbound.Name, outbound.OutAddr, err)
		chChan.Close()
		return
	}

	log.Printf("Outbound %s accept dial success - connected to %s", outbound.Name, outbound.OutAddr)

	//go ssh.DiscardRequests(chReqs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range chReqs {
			if req == nil {
				chChan.Close()
				return
			}
			if req.WantReply {
				log.Printf("Outbound %s acept chReqs closed", outbound.Name)
				req.Reply(false, nil)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err = io.Copy(tcpConn, chChan)
		//log.Printf("Outbound %s accept io.Copy from SSH ended", outbound.Name)
		tcpConn.Close()
		chChan.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err = io.Copy(chChan, tcpConn)
		//log.Printf("Outbound %s accept io.Copy from TCP ended", outbound.Name)
		chChan.Close()
		tcpConn.Close()
	}()
}
