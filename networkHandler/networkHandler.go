package networkHandler

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/yuvalrakavy/goPool"
)

const MaxPacketSize = 4096

// Role determins if the network handler act as server or client
//
//   Role       Client			Server
//                  Request  -->
//                  <--  Reply
//

type RawPacket struct {
	PacketLength  int
	PacketBytes   []byte
	RemoteAddress net.Addr
}

type pendingRequest struct {
	requestAckChannel chan interface{}
	replyChannel      chan *RawPacket
}

type addPendingRequestMessage struct {
	requestNumberChannel chan int
	pendingRequest       pendingRequest
}

type Connection struct {
	UdpConnection           *net.UDPConn   // listen to incoming UDP packets on this conn
	IncomingRequestsChannel chan RawPacket // Channel for receiveing incoming request (i.e. packets which are not replies)

	nextRequestNumber int                           // Sequence number to send with next request
	pendingRequests   map[int]pendingRequest        // pending requests that were not yet acknowledged
	noAckChannel      chan int                      // channel in which requestSenders report failure
	addRequestChannel chan addPendingRequestMessage // channel for adding a pending request
}

// Implement that on packet to allow to handle request/reply association
type PacketReplyParser interface {
	IsReply() bool         // Is this packet a replay packet
	GetRequestNumber() int // The request sequence number for which this packet is a reply
}

type EncodablePacket interface {
	Encode() []byte
}

func StartIncomingPacketsHandling(pool *goPool.GoPool, udpAddress string, getReplyParser func(RawPacket) PacketReplyParser) (*Connection, error) {
	myAddress, err := net.ResolveUDPAddr("udp", udpAddress)
	if err != nil {
		return nil, err
	}

	incomingPacketsConn, err := net.ListenUDP("udp", myAddress)
	if err != nil {
		return nil, err
	}

	connection := Connection{
		UdpConnection:           incomingPacketsConn,
		nextRequestNumber:       1,
		pendingRequests:         make(map[int]pendingRequest),
		noAckChannel:            make(chan int),
		addRequestChannel:       make(chan addPendingRequestMessage),
		IncomingRequestsChannel: make(chan RawPacket, 2),
	}

	go func() {
		pool.Enter()
		defer pool.Leave()

		incomingPacketsChannel := make(chan RawPacket)
		shouldTerminate := false

		go incomingPacketsHandler(incomingPacketsConn, incomingPacketsChannel, &shouldTerminate)

		for {
			select {
			case <-pool.Done:
				shouldTerminate = true
				fmt.Println("Closing UDP connection")
				connection.UdpConnection.Close()

				for _, pendingRequest := range connection.pendingRequests {
					close(pendingRequest.requestAckChannel)
				}

				return

			case addPendingRequestMessage := <-connection.addRequestChannel:
				requestNumber := connection.allocateRequestNumber()
				connection.pendingRequests[requestNumber] = addPendingRequestMessage.pendingRequest
				addPendingRequestMessage.requestNumberChannel <- requestNumber

			case rawPacket := <-incomingPacketsChannel:
				packetReplyParser := getReplyParser(rawPacket)

				if packetReplyParser != nil && packetReplyParser.IsReply() {
					requestNumber := packetReplyParser.GetRequestNumber()
					pendingRequest, hasPendingRequest := connection.pendingRequests[requestNumber]

					if hasPendingRequest {
						close(pendingRequest.requestAckChannel)
						delete(connection.pendingRequests, requestNumber)
						pendingRequest.replyChannel <- &rawPacket
					} else {
						log.Printf("Received reply packet for non-pending request# %d\n", requestNumber)
					}
				} else {
					connection.IncomingRequestsChannel <- rawPacket
				}

			case failedRequestNumber := <-connection.noAckChannel:
				{
					pendingRequest, hasPendingRequest := connection.pendingRequests[failedRequestNumber]

					if hasPendingRequest {
						close(pendingRequest.requestAckChannel)
						close(pendingRequest.replyChannel)
						delete(connection.pendingRequests, failedRequestNumber)
					} else {
						log.Printf("No reply was received for request# %d - this request is no longer pending\n", failedRequestNumber)
					}

				}
			}
		}
	}()

	return &connection, nil
}

func (connection *Connection) allocateRequestNumber() int {
	for i := 0; i < 20; i++ {
		sequenceNumber := connection.nextRequestNumber
		connection.nextRequestNumber++

		_, hasPendingRequest := connection.pendingRequests[sequenceNumber]

		if !hasPendingRequest {
			return sequenceNumber
		}
	}

	panic("NetworkManager: could not allocate unused request sequence number (probably bug)")
}

func (connection *Connection) CreateRequest(requestSender func(requestNumber int), timeout time.Duration, retries int) chan *RawPacket {
	requestNumberChannel := make(chan int)

	pendingRequest := pendingRequest{
		requestAckChannel: make(chan interface{}),
		replyChannel:      make(chan *RawPacket),
	}

	connection.addRequestChannel <- addPendingRequestMessage{
		requestNumberChannel: requestNumberChannel,
		pendingRequest:       pendingRequest,
	}

	requestNumber := <-requestNumberChannel

	go func() {
		retry := 0

		requestSender(requestNumber) // Send the request

		for {
			select {
			case <-pendingRequest.requestAckChannel:
				return // Request was ack, no need to retry

			case <-time.After(timeout):
				retry++
				if retry < retries {
					log.Printf("Timeout for reply on request# %d, resending request", requestNumber)
					requestSender(requestNumber) // Send request again
				} else {
					connection.noAckChannel <- requestNumber
					return
				}
			}
		}
	}()

	return pendingRequest.replyChannel
}

func incomingPacketsHandler(conn *net.UDPConn, incomingPacketsChannel chan<- RawPacket, shouldTerminate *bool) {

	for {
		packetBytes := make([]byte, MaxPacketSize)
		packetLength, remoteAddr, err := conn.ReadFrom(packetBytes)

		if err != nil {
			if *shouldTerminate {
				fmt.Println("Packet processing terminated")
				return
			} else {
				panic(err)
			}
		}

		incomingPacketsChannel <- RawPacket{PacketBytes: packetBytes, PacketLength: packetLength, RemoteAddress: remoteAddr}
	}
}

func (rawPacket RawPacket) SendReply(udpConnection *net.UDPConn, packet EncodablePacket) error {
	packetBytes := packet.Encode()

	_, err := udpConnection.WriteTo(packetBytes, rawPacket.RemoteAddress)
	return err
}
