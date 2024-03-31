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

	"golang.org/x/crypto/ssh"
)

const (
	PP_SID         = "pp-sid/"
	PP_PRIVATE_KEY = PP_SID + "privateKey"
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
}

// Inbound side of the Tunnel - incoming tcp connections from local clients
type Inbound struct {
	// tcp peers
	Name        string
	TcpListener *net.TCPListener
}

type Outbound struct {
	// tcp peers
	Name    string
	OutAddr string
}

type Outbounds struct {
	list []*Outbound
}

type Inbounds struct {
	list []*Inbound
}

func (outbounds *Outbounds) Add(tag string) {
	splits := strings.Split(tag, ":")
	var port, host, name string
	if len(splits) == 2 {
		name = splits[0]
		port = splits[1]
		host = "127.0.0.1"

	} else if len(splits) == 3 {
		name = splits[0]
		host = splits[1]
		port = splits[2]

	} else {
		log.Fatalf("Outbound Add wrong Tag: %s", tag)
	}

	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		log.Fatalf("outbound Add Port '%s' - Err: %v", port, err)
	}

	outbound := &Outbound{
		Name:    name,
		OutAddr: host + ":" + port,
	}
	outbounds.list = append(outbounds.list, outbound)
}
func (inbounds *Inbounds) Add(tag string, forceInPort string) error {
	splits := strings.Split(tag, ":")
	if len(splits) != 2 {
		return fmt.Errorf("Inbound Add wrong Tag: %s", tag)
	}
	name := splits[0]
	inPort := splits[1]
	if forceInPort != "" {
		inPort = forceInPort
	}

	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%s", inPort))
	if err != nil {
		return fmt.Errorf("NewInbound ResolveTCPAddr: %v", err)
	}
	tcpListener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("NewInbound ListenTCP: %v", err)
	}
	log.Printf("NewInbound Listening to port %s", inPort)

	inbound := &Inbound{
		TcpListener: tcpListener,
		Name:        name,
	}
	inbounds.list = append(inbounds.list, inbound)
	return nil
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
	go ssh.DiscardRequests(sshReqs)

	go func() {
		<-ctx.Done()
		peer.Close("Context Canceled")
	}()

	go func() {
		for ch := range chans {
			switch ch.ChannelType() {
			default:
				log.Printf("%s Phase: NewSshPeer rejected channel for %s", phase, ch.ChannelType())
				ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", ch.ChannelType()))
			case "tunnel":
				name := string(ch.ExtraData())
				outbound := peer.outbounds[name]
				if outbound == nil {
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
					outbound.acceptProxy(chChan, chReqs, sid)
				} else {
					outbound.accept(chChan, chReqs)
				}

			}
		}
		log.Printf("%s Phase: Ssh chans channel closed", phase)
		peer.Close("Chans gorutine terminated") // signal done in case termination happened in peer
	}()
	return peer
}

func (peer *SshPeer) Wait() {
	<-peer.done
}

func (peer *SshPeer) Close(who string) {
	if peer.terminated == "" {
		log.Printf("%s Phase: Peer Done by >>> %s <<<", peer.phase, who)
		peer.terminated = who
		peer.sshConn.Close()
		for inPort := range peer.inbounds {
			peer.DelInbound(inPort)
		}
		peer.done <- true
	}
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) AddInbound(inbound *Inbound) error {
	go func() {
		for {
			tcpConn, err := inbound.TcpListener.Accept()
			if err != nil {
				log.Printf("%s Phase: Inbound Accept error: %s - shutdown ssh", peer.phase, err)
				peer.sshConn.Close()                            // Shutdown other side
				peer.Close("inbound.tcpListener.Accept failed") // Shutdown this peer
				return
			}
			log.Printf("%s Phase: Inbound Accept: %s", peer.phase, inbound.Name)
			NewInboundInstance(tcpConn, peer, inbound)
		}
	}()
	peer.inbounds[inbound.Name] = inbound
	return nil
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) DelInbound(inPort string) {
	if inbound, found := peer.inbounds[inPort]; found {
		delete(peer.inbounds, inPort)
		inbound.TcpListener.Close()
	}
}

func NewInboundInstance(tcpConn io.ReadWriteCloser, peer *SshPeer, inbound *Inbound) {
	sshChan, channelReqs, err := peer.sshConn.OpenChannel("tunnel", []byte(inbound.Name))
	if err != nil {
		log.Printf("%s Phase: NewInboundInstance OpenChannel %s error: %s", peer.phase, inbound.Name, err)
		return
	}
	log.Printf("%s Phase: NewInboundInstance OpenChannel opening tunnel for: %s", peer.phase, inbound.Name)
	go ssh.DiscardRequests(channelReqs)

	go func() {
		_, err = io.Copy(tcpConn, sshChan)
		log.Printf("%s Phase: Inbound io.Copy from SSH ended on %s", peer.phase, inbound.Name)
		tcpConn.Close()
		sshChan.Close()
	}()

	go func() {
		_, err = io.Copy(sshChan, tcpConn)
		log.Printf("%s Phase: Inbound io.Copy from TCP ended on %s", peer.phase, inbound.Name)
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

func (outbound *Outbound) acceptProxy(chChan ssh.Channel, chReqs <-chan *ssh.Request, sid string) {
	remoteUrl, err := url.Parse("http://" + outbound.OutAddr)
	if err != nil {
		log.Printf("acceptProxy error parsing address %s: %v", outbound.OutAddr, err)
		return
	}

	// The proxy is a Handler - it has a ServeHTTP method
	proxy := httputil.NewSingleHostReverseProxy(remoteUrl)
	proxy.Transport = http.DefaultTransport
	log.Printf("acceptProxy Setting up for sid %s", sid)

	go ssh.DiscardRequests(chReqs)
	go func() {
		for {
			bior := bufio.NewReader(chChan)
			req, err := http.ReadRequest(bior)
			if err != nil {
				log.Printf("acceptProxy Error in proxy ReadRequest: %v", err)
				chChan.Close()
				return
			}
			req.URL.Path = SID(sid).urlModifier(req.URL.Path)
			req.URL.Scheme = "http"
			req.URL.Host = outbound.OutAddr
			log.Printf("acceptProxy modified URL to %s of host %s", req.URL.Path, req.URL.Host)

			resp, err := proxy.Transport.RoundTrip(req)
			if err != nil {
				log.Printf("acceptProxy Error in proxy.Transport.RoundTrip: %v", err)
				chChan.Close()
				return
			}
			err = resp.Write(chChan)
			if err != nil {
				log.Printf("acceptProxy Error in proxy resp.Write: %v", err)
				chChan.Close()
				return
			}
			log.Printf("acceptProxy received a response for %s", req.URL.Path)
		}
	}()
}

func (outbound *Outbound) accept(chChan ssh.Channel, chReqs <-chan *ssh.Request) {
	tcpConn, err := net.Dial("tcp", outbound.OutAddr)
	if err != nil {
		log.Printf("Outbound dial to %s address %s err: %s - closing channel", outbound.Name, outbound.OutAddr, err)
		chChan.Close()
		return
	}

	log.Printf("Outbound dial success for %s - connected to %s", outbound.Name, outbound.OutAddr)

	go ssh.DiscardRequests(chReqs)

	go func() {
		_, err = io.Copy(tcpConn, chChan)
		log.Printf("Outbound io.Copy from SSH ended on %s", outbound.Name)
		tcpConn.Close()
		chChan.Close()
	}()

	go func() {
		_, err = io.Copy(chChan, tcpConn)
		log.Printf("Outbound io.Copy from TCP ended on %s", outbound.Name)
		chChan.Close()
		tcpConn.Close()
	}()
}
