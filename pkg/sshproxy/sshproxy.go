package sshproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

type SshPeer struct {
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
	OutPort     string
	TcpListener *net.TCPListener
}

type Outbound struct {
	// tcp peers
	OutPort string
}

type Outbounds struct {
	list []*Outbound
}

type Inbounds struct {
	list []*Inbound
}

func (outbounds *Outbounds) Add(outPort int) {
	outbound := &Outbound{
		OutPort: strconv.Itoa(outPort),
	}
	outbounds.list = append(outbounds.list, outbound)
}
func (inbounds *Inbounds) Add(outPort int, inPort int) error {
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", inPort))
	if err != nil {
		return fmt.Errorf("NewInbound ResolveTCPAddr: %v", err)
	}
	tcpListener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("NewInbound ListenTCP: %v", err)
	}
	log.Printf("NewInbound Listening to port %d", inPort)

	inbound := &Inbound{
		TcpListener: tcpListener,
		OutPort:     strconv.Itoa(outPort),
	}
	inbounds.list = append(inbounds.list, inbound)
	return nil
}

// NewSshPeer
func NewSshPeer(ctx context.Context, sshConn ssh.Conn, chans <-chan ssh.NewChannel, sshReqs <-chan *ssh.Request) *SshPeer {
	peer := &SshPeer{
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
				log.Printf("NewSshPeer rejected channel for %s", ch.ChannelType())
				ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", ch.ChannelType()))
			case "tunnel":
				inPort := string(ch.ExtraData())

				outbound := peer.outbounds[inPort]
				if outbound == nil {
					ch.Reject(ssh.UnknownChannelType, fmt.Sprintf("NewSshPeer rejected tunnel channel  - port not allowed: %s", inPort))
					continue
				}
				chChan, chReqs, err := ch.Accept()
				if err != nil {
					log.Printf("NewSshPeer failed to accept tunnel channel: %s", err)
					peer.Close("Accept failed")
				}
				log.Printf("NewSshPeer  - peer requested a tunnel channel for port %s", inPort)
				outbound.accept(chChan, chReqs)
			}
		}
		log.Printf("Ssh chans channel closed")
		peer.Close("Chans gorutine terminated") // signal done in case termination happened in peer
	}()
	return peer
}

func (peer *SshPeer) Wait() {
	<-peer.done
}

func (peer *SshPeer) Close(who string) {
	if peer.terminated == "" {
		log.Printf("Peer Done by >>> %s <<<", who)
		peer.terminated = who
		peer.sshConn.Close()
		peer.done <- true
	}
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) AddInbound(inbound *Inbound) error {
	go func() {
		for {
			tcpConn, err := inbound.TcpListener.Accept()
			if err != nil {
				log.Printf("NewInbound Accept error: %s - shutdown ssh", err)
				peer.sshConn.Close()                            // Shutdown other side
				peer.Close("inbound.tcpListener.Accept failed") // Shutdown this peer
			}
			NewInboundInstance(tcpConn, peer, inbound)
		}
	}()
	peer.inbounds[inbound.OutPort] = inbound
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

	sshChan, channelReqs, err := peer.sshConn.OpenChannel("tunnel", []byte(inbound.OutPort))
	if err != nil {
		log.Printf("NewInboundInstance OpenChannel error: %s", err)
		return
	}
	log.Printf("NewInboundInstance OpenChannel opening tunnel for: %s", inbound.OutPort)
	go ssh.DiscardRequests(channelReqs)

	go func() {
		_, err = io.Copy(tcpConn, sshChan)
		log.Printf("NewInboundInstance io.Copy from sshChan to tcpConn err: %s", err)
		tcpConn.Close()
		sshChan.Close()
	}()

	go func() {
		_, err = io.Copy(sshChan, tcpConn)
		log.Printf("NewInboundInstance io.Copy from tcpConn to sshChan err: %s", err)
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
	peer.outbounds[outbound.OutPort] = outbound
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) DelOutbound(outPort string) {
	delete(peer.outbounds, outPort)
}

func (outbound *Outbound) accept(chChan ssh.Channel, chReqs <-chan *ssh.Request) {

	tcpConn, err := net.Dial("tcp", "127.0.0.1:"+outbound.OutPort)
	if err != nil {
		log.Printf("Outbound dial error: %s - closing channel", err)
		chChan.Close()
		return
	}

	log.Printf("Outbound dial success - connected to port %s", outbound.OutPort)

	go ssh.DiscardRequests(chReqs)

	go func() {
		_, err = io.Copy(tcpConn, chChan)
		log.Printf("Outbound io.Copy from chChan to tcpConn: %s", err)
		tcpConn.Close()
		chChan.Close()
	}()

	go func() {
		_, err = io.Copy(chChan, tcpConn)
		log.Printf("Outbound io.Copy from tcpConn to chChan: %s", err)
		chChan.Close()
		tcpConn.Close()
	}()

}
