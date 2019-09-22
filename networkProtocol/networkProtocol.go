package networkProtocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const TrainDetectorAddress = ":3000"
const MinProtocolVersion = 1
const MaxProtocolVersion = 1
const CurrentProtocolVersion = 1

// VL6180 control registers
// nolint:go-lint,varcheck,deadcode
const (
	PacketClassRequest      = 0x00
	PacketClassReply        = 0x80
	PacketClassNotification = PacketClassRequest
	PacketClassAcknowledge  = PacketClassReply

	PacketTypeIdentify        = 0
	PacketTypeIdentifyRequest = PacketTypeIdentify | PacketClassRequest
	PacketTypeIdentifyReply   = PacketTypeIdentify | PacketClassReply

	PacketTypeIdentifyAcknowledge = 1 | PacketClassAcknowledge

	PacketTypeConfig        = 2
	PacketTypeConfigRequest = PacketTypeConfig | PacketClassRequest
	PacketTypeConfigReply   = PacketTypeConfig | PacketClassReply

	PacketTypeGetState        = 3
	PacketTypeGetStateRequest = PacketTypeGetState | PacketClassRequest
	PacketTypeGetStateReply   = PacketTypeGetState | PacketClassReply

	PacketTypeSubscribe       = 4
	PacketTypeSubscribeRequst = PacketTypeSubscribe | PacketClassRequest
	PacketTypeSubscribeReply  = PacketTypeSubscribe | PacketClassReply

	PacketTypeUnsubscribe       = 5
	PacketTypeUnsubscribeRequst = PacketTypeUnsubscribe | PacketClassRequest
	PacketTypeUnsubscribeReply  = PacketTypeUnsubscribe | PacketClassReply

	PacketTypeStateChanged             = 6
	PacketTypeStateChangedNotification = PacketTypeStateChanged | PacketClassNotification
	PacketTypeStateChangedAcknowledge  = PacketTypeStateChanged | PacketClassAcknowledge
)

var PacketTypeNameMap = map[byte]string{
	PacketTypeIdentifyRequest:          "Identify Request",
	PacketTypeIdentifyReply:            "Identify Reply",
	PacketTypeIdentifyAcknowledge:      "Identify reply acknowlede",
	PacketTypeConfigRequest:            "Config request",
	PacketTypeConfigReply:              "Config reply",
	PacketTypeGetStateRequest:          "GetState request",
	PacketTypeGetStateReply:            "GetState reply",
	PacketTypeSubscribeRequst:          "Subscribe request",
	PacketTypeSubscribeReply:           "Subscribe reply",
	PacketTypeUnsubscribeRequst:        "Unsubscribe request",
	PacketTypeUnsubscribeReply:         "Unsubscribe reply",
	PacketTypeStateChangedNotification: "State changed notification",
	PacketTypeStateChangedAcknowledge:  "State changed acknowledged",
}

type RequestNumber uint16

type PacketString string

type PacketHeader struct {
	PacketType           byte
	PacketTypeCompliment byte
	RequestNumber        RequestNumber
}

func NewHeader(packetType byte, requestNumber RequestNumber) PacketHeader {
	return PacketHeader{PacketType: packetType, PacketTypeCompliment: ^packetType, RequestNumber: requestNumber}
}

func (header *PacketHeader) EncodeTo(buffer *bytes.Buffer) {
	if err := binary.Write(buffer, binary.LittleEndian, &header); err != nil {
		panic(err)
	}
}

func (s PacketString) EncodeTo(buffer *bytes.Buffer) {
	lengthBuffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBuffer, uint16(len(s)))
	if _, err := buffer.Write(lengthBuffer); err != nil {
		panic(err)
	}

	if n, err := buffer.WriteString(string(s)); err != nil {
		panic(err)
	} else if n != len(s) {
		panic("Inconsistent string encoding")
	}
}

func (packetReader TrainDetectorPacketReader) DecodeString() (PacketString, error) {
	lengthBytes := make([]byte, 2)
	if _, err := packetReader.Read(lengthBytes); err != nil {
		return "", fmt.Errorf("Reading string length: %w", err)
	}

	length := binary.LittleEndian.Uint16(lengthBytes)
	stringBytes := make([]byte, length)
	if _, err := packetReader.Read(stringBytes); err != nil {
		return "", fmt.Errorf("Reading string body: %w", err)
	}

	return PacketString(stringBytes), nil
}

func (packetReader TrainDetectorPacketReader) Decode() (interface{}, error) {
	header, err := packetReader.Header()

	if err != nil {
		return nil, err
	}

	if !header.IsValid() {
		return nil, fmt.Errorf("Invalid packet bytes (type != ^typeCompliment")
	}

	switch {
	case header.PacketType == PacketTypeIdentifyRequest:
		return packetReader.DecodeIdentifyRequest(&header)

	case header.PacketType == PacketTypeIdentifyReply:
		return packetReader.DecodeIdentifyReply(&header)

	case header.PacketType == PacketTypeIdentifyAcknowledge:
		return packetReader.DecodeIdentifyAcknowledge(&header)

	default:
		return nil, fmt.Errorf("Packet seems to be valid, but has unsupported type %x", header.PacketType)
	}
}

// IdentifyRequestPacket - packet is UDP broadcasted to all clients. Each client will responde with
//   IdentifyReplyPacket
type IdentifyRequestPacket struct {
	Header             PacketHeader
	MinProtocolVersion byte // Minmum protocol version supported by server
	MaxProtocolVesion  byte // Maximum protocol version that server supports
}

func NewIdetifyRequst(requestNumber RequestNumber) IdentifyRequestPacket {
	return IdentifyRequestPacket{
		Header:             NewHeader(PacketTypeIdentifyRequest, requestNumber),
		MinProtocolVersion: MinProtocolVersion,
		MaxProtocolVesion:  MaxProtocolVersion,
	}
}

func (packet *IdentifyRequestPacket) Encode() []byte {
	b := bytes.NewBuffer(nil)
	if err := binary.Write(b, binary.LittleEndian, packet); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeIdentifyRequest(header *PacketHeader) (IdentifyRequestPacket, error) {
	minProtocolVersion, err := packetReader.ReadByte()
	if err != nil {
		return IdentifyRequestPacket{}, err
	}

	maxProtocolVersion, err := packetReader.ReadByte()
	if err != nil {
		return IdentifyRequestPacket{}, err
	}

	return IdentifyRequestPacket{
		Header:             *header,
		MinProtocolVersion: minProtocolVersion,
		MaxProtocolVesion:  maxProtocolVersion,
	}, nil
}

// IdentifyRequestReply - packet is sent as a reply to IdentifyRequest.
//  The client will resend this packet if after no IdentifyAcknowledge is not received
type IdentifyReplyPacket struct {
	Header          PacketHeader
	ProtocolVersion byte         // Protocol version to be used (must be in the reange IdentifyRequest.MinProtocolVersion...IdentifyRequest.MaxProtocolVersion)
	MacAddress      PacketString // Mac address of this device
	Name            PacketString // Name of this device
}

func NewIdetifyReply(requestNumber RequestNumber, macAddress PacketString, name PacketString) IdentifyReplyPacket {
	return IdentifyReplyPacket{
		Header:          NewHeader(PacketTypeIdentifyReply, requestNumber),
		ProtocolVersion: CurrentProtocolVersion,
		MacAddress:      macAddress,
		Name:            name,
	}
}

func (packet *IdentifyReplyPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	packet.MacAddress.EncodeTo(buffer)
	packet.Name.EncodeTo(buffer)

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeIdentifyReply(header *PacketHeader) (IdentifyReplyPacket, error) {
	protocolVersion, err := packetReader.ReadByte()
	if err != nil {
		return IdentifyReplyPacket{}, err
	}

	macAddress, err := packetReader.DecodeString()
	if err != nil {
		return IdentifyReplyPacket{}, err
	}

	name, err := packetReader.DecodeString()
	if err != nil {
		return IdentifyReplyPacket{}, err
	}

	return IdentifyReplyPacket{
		Header:          *header,
		ProtocolVersion: protocolVersion,
		MacAddress:      macAddress,
		Name:            name,
	}, nil
}

// IdentifyAcknowledge - Send as a when IdentifyReply packet is received.
// The client will stop sending IdentifyReply packets
type IdentifyAcknowledgePacket struct {
	Header PacketHeader
}

func NewIdentifyAcknowledge(requestNumber RequestNumber) IdentifyAcknowledgePacket {
	return IdentifyAcknowledgePacket{
		Header: NewHeader(PacketTypeIdentifyAcknowledge, requestNumber),
	}
}

func (packet *IdentifyAcknowledgePacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)
	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeIdentifyAcknowledge(header *PacketHeader) (IdentifyAcknowledgePacket, error) {
	return IdentifyAcknowledgePacket{
		Header: *header,
	}, nil
}
