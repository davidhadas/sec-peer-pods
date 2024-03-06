package sshproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"

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
	InHost      string
	InPort      string
	tcpListener *net.TCPListener
}

type Outbound struct {
	// tcp peers
	InPort  string
	OutHost string // default is 127.0.0.1
	OutPort string
}

type Outbounds struct {
	list []*Outbound
}

type Inbounds struct {
	list []*Inbound
}

func (outbounds *Outbounds) Add(inPort string, outPort string, outHost string) {
	outbound := &Outbound{
		InPort:  inPort,
		OutPort: outPort,
		OutHost: outHost,
	}
	outbounds.list = append(outbounds.list, outbound)
}
func (inbounds *Inbounds) Add(inPort string) {
	inbound := &Inbound{
		InHost: "127.0.0.1",
		InPort: inPort,
	}
	inbounds.list = append(inbounds.list, inbound)
}

// NewSshPeer
func NewSshPeer(ctx context.Context, done chan bool, sshConn ssh.Conn, chans <-chan ssh.NewChannel, sshReqs <-chan *ssh.Request) *SshPeer {
	peer := &SshPeer{
		sshConn:   sshConn,
		ctx:       ctx,
		done:      done,
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
		log.Printf("Chans gorutine terminating!!")
		peer.Close("Chans gorutine terminated") // signal done in case termination happened in peer
	}()
	return peer
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
	addr, err := net.ResolveTCPAddr("tcp", inbound.InHost+":"+inbound.InPort)
	if err != nil {
		return fmt.Errorf("NewInbound ResolveTCPAddr: %s", err)
	}
	tcpListener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("NewInbound ListenTCP: %s", err)
	}
	inbound.tcpListener = tcpListener
	log.Printf("NewInbound Listening to port %s", inbound.InPort)

	go func() {
		for {
			tcpConn, err := inbound.tcpListener.Accept()
			if err != nil {
				log.Printf("NewInbound Accept error: %s - shutdown ssh", err)
				peer.sshConn.Close()                            // Shutdown other side
				peer.Close("inbound.tcpListener.Accept failed") // Shutdown this peer
			}
			NewInboundInstance(tcpConn, peer, inbound)
		}
	}()
	peer.inbounds[inbound.InPort] = inbound
	return nil
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) DelInbound(inPort string) {
	if inbound, found := peer.inbounds[inPort]; found {
		delete(peer.inbounds, inPort)
		inbound.tcpListener.Close()
	}
}

func NewInboundInstance(tcpConn io.ReadWriteCloser, peer *SshPeer, inbound *Inbound) {

	sshChan, channelReqs, err := peer.sshConn.OpenChannel("tunnel", []byte(inbound.InPort))
	if err != nil {
		log.Printf("NewInboundInstance OpenChannel error: %s", err)
		return
	}
	log.Printf("NewInboundInstance OpenChannel opening tunnel for: %s", inbound.InPort)
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
	peer.outbounds[outbound.InPort] = outbound
}

// NewInbound create an Inbound and listen to incomming client connections
func (peer *SshPeer) DelOutbound(inPort string) {
	if _, found := peer.outbounds[inPort]; found {
		delete(peer.outbounds, inPort)
	}
}

func (outbound *Outbound) accept(chChan ssh.Channel, chReqs <-chan *ssh.Request) {

	tcpConn, err := net.Dial("tcp", outbound.OutHost+":"+outbound.OutPort)
	if err != nil {
		log.Printf("Outbound dial error: %s - closing channel", err)
		chChan.Close()
		return
	}

	log.Printf("Outbound dial success - connected to host %s port %s", outbound.OutHost, outbound.OutPort)

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
