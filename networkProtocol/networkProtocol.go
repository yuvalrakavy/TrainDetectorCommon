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

	PacketTypePleaseIdentify = 0

	PakcketTypeIdentification           = 1
	PacketTypeIdentificationInfo        = PakcketTypeIdentification | PacketClassRequest
	PacketTypeIdentificationAcknowledge = PakcketTypeIdentification | PacketClassAcknowledge

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

type PacketRequestNumber uint16

type PacketString string

type PacketHeader struct {
	PacketType           byte
	PacketTypeCompliment byte
	PacketRequestNumber  PacketRequestNumber
}

func NewHeader(packetType byte, requestNumber int) PacketHeader {
	return PacketHeader{PacketType: packetType, PacketTypeCompliment: ^packetType, PacketRequestNumber: PacketRequestNumber(requestNumber)}
}

func (header *PacketHeader) EncodeTo(buffer *bytes.Buffer) {
	if err := binary.Write(buffer, binary.LittleEndian, header); err != nil {
		panic(err)
	}
}

func (header PacketHeader) RequestNumber() int {
	return int(header.PacketRequestNumber)
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
	case header.PacketType == PacketTypePleaseIdentify:
		return packetReader.DecodePleaseIdentify(&header)

	case header.PacketType == PacketTypeIdentificationInfo:
		return packetReader.DecodeIdentificationInfo(&header)

	case header.PacketType == PacketTypeIdentificationAcknowledge:
		return packetReader.DecodeIdentificationAcknowledge(&header)

	case header.PacketType == PacketTypeGetStateRequest:
		return packetReader.DecodeGetStateRequest(&header)

	case header.PacketType == PacketTypeGetStateReply:
		return packetReader.DecodeGetStateReply(&header)

	case header.PacketType == PacketTypeSubscribeRequst:
		return packetReader.DecodeSubscribeRequest(&header)

	case header.PacketType == PacketTypeSubscribeReply:
		return packetReader.DecodeSubscribeReply(&header)

	case header.PacketType == PacketTypeUnsubscribeRequst:
		return packetReader.DecodeUnsubscribeRequest(&header)

	case header.PacketType == PacketTypeUnsubscribeReply:
		return packetReader.DecodeUnsubscribeReply(&header)

	case header.PacketType == PacketTypeStateChangedNotification:
		return packetReader.DecodeStateChangedNotification(&header)

	case header.PacketType == PacketTypeStateChangedAcknowledge:
		return packetReader.DecodeStateChangedAcknowledge(&header)

	default:
		return nil, fmt.Errorf("Packet seems to be valid, but has unsupported type %x", header.PacketType)
	}
}

// PleaseIdentify - packet is UDP broadcasted to all clients. Each client will responde with
//   IdentificationInfoPacket
type PleaseIdentifyPacket struct {
	Header             PacketHeader
	MinProtocolVersion byte // Minmum protocol version supported by server
	MaxProtocolVesion  byte // Maximum protocol version that server supports
}

func NewPleaseIdentify() *PleaseIdentifyPacket {
	return &PleaseIdentifyPacket{
		Header:             NewHeader(PacketTypePleaseIdentify, 0),
		MinProtocolVersion: MinProtocolVersion,
		MaxProtocolVesion:  MaxProtocolVersion,
	}
}

func (packet *PleaseIdentifyPacket) Encode() []byte {
	b := bytes.NewBuffer(nil)
	if err := binary.Write(b, binary.LittleEndian, packet); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodePleaseIdentify(header *PacketHeader) (*PleaseIdentifyPacket, error) {
	minProtocolVersion, err := packetReader.ReadByte()
	if err != nil {
		return nil, err
	}

	maxProtocolVersion, err := packetReader.ReadByte()
	if err != nil {
		return nil, err
	}

	return &PleaseIdentifyPacket{
		Header:             *header,
		MinProtocolVersion: minProtocolVersion,
		MaxProtocolVesion:  maxProtocolVersion,
	}, nil
}

// IdentificationInfo - packet is sent as a reply to IdentifyRequest.
//  The client will resend this packet if after no IdentifyAcknowledge is not received
type IndenticiationInfoPacket struct {
	Header          PacketHeader
	ProtocolVersion byte         // Protocol version to be used (must be in the reange IdentifyRequest.MinProtocolVersion...IdentifyRequest.MaxProtocolVersion)
	SensorsCount    uint16       // Number of sensors
	Name            PacketString // Name of this device
}

func NewIdentificationInfo(requestNumber int, sensorCount int, name PacketString) *IndenticiationInfoPacket {
	return &IndenticiationInfoPacket{
		Header:          NewHeader(PacketTypeIdentificationInfo, requestNumber),
		ProtocolVersion: CurrentProtocolVersion,
		SensorsCount:    uint16(sensorCount),
		Name:            name,
	}
}

func (packet *IndenticiationInfoPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)
	binary.Write(buffer, binary.LittleEndian, &packet.ProtocolVersion)
	binary.Write(buffer, binary.LittleEndian, &packet.SensorsCount)
	packet.Name.EncodeTo(buffer)

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeIdentificationInfo(header *PacketHeader) (*IndenticiationInfoPacket, error) {
	protocolVersion, err := packetReader.ReadByte()
	if err != nil {
		return nil, err
	}

	var sensorCount uint16
	err = binary.Read(packetReader, binary.LittleEndian, &sensorCount)
	if err != nil {
		return nil, err
	}

	name, err := packetReader.DecodeString()
	if err != nil {
		return nil, err
	}

	return &IndenticiationInfoPacket{
		Header:          *header,
		ProtocolVersion: protocolVersion,
		SensorsCount:    sensorCount,
		Name:            name,
	}, nil
}

// IdentifyAcknowledge - Send as a when IdentifyReply packet is received.
// The client will stop sending IdentifyReply packets
type IdentificationAcknowledgePacket struct {
	Header PacketHeader
}

func NewIdentificationAcknowledge(requestNumber int) *IdentificationAcknowledgePacket {
	return &IdentificationAcknowledgePacket{
		Header: NewHeader(PacketTypeIdentificationAcknowledge, requestNumber),
	}
}

func (packet *IdentificationAcknowledgePacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)
	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeIdentificationAcknowledge(header *PacketHeader) (*IdentificationAcknowledgePacket, error) {
	return &IdentificationAcknowledgePacket{
		Header: *header,
	}, nil
}

// GetStateRequest
//   The controller will response with the current sensor cover/uncover state
type GetStateRequestPacket struct {
	Header PacketHeader
}

func NewGetStateRequest(requestNumber int) *GetStateRequestPacket {
	return &GetStateRequestPacket{
		Header: NewHeader(PacketTypeGetStateRequest, requestNumber),
	}
}

func (packet *GetStateRequestPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)
	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeGetStateRequest(header *PacketHeader) (*GetStateRequestPacket, error) {
	return &GetStateRequestPacket{
		Header: *header,
	}, nil
}

// GetStateReply
//   Reply to GetStateRequest with the current sensor state
type GetStateReplyPacket struct {
	Header  PacketHeader
	Version uint32
	States  []bool // True - sensor is covered, false - sensor is not covered
}

func NewGetStateReply(requestNumber int, version uint32, states []bool) *GetStateReplyPacket {
	return &GetStateReplyPacket{
		Header:  NewHeader(PacketTypeGetStateReply, requestNumber),
		Version: version,
		States:  states,
	}
}

func (packet *GetStateReplyPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	// write version
	if err := binary.Write(buffer, binary.LittleEndian, &packet.Version); err != nil {
		panic(err)
	}

	// Write count
	buffer.WriteByte(byte(len(packet.States)))
	if err := binary.Write(buffer, binary.LittleEndian, packet.States); err != nil {
		panic(err)
	}

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeGetStateReply(header *PacketHeader) (*GetStateReplyPacket, error) {
	var version uint32

	if err := binary.Read(packetReader, binary.LittleEndian, &version); err != nil {
		panic(err)
	}

	count, err := packetReader.ReadByte()
	if err != nil {
		return nil, err
	}

	states := make([]bool, count)
	if err := binary.Read(packetReader, binary.LittleEndian, &states); err != nil {
		return nil, err
	}

	return &GetStateReplyPacket{
		Header:  *header,
		Version: version,
		States:  states,
	}, nil
}

// SubscribeRequest - get notified when sensor value is changed
type SubscribeRequestPacket struct {
	Header PacketHeader
}

func NewSubcribeRequestPacket(requestNumber int) *SubscribeRequestPacket {
	return &SubscribeRequestPacket{
		Header: NewHeader(PacketTypeSubscribeRequst, requestNumber),
	}
}

func (packet *SubscribeRequestPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeSubscribeRequest(header *PacketHeader) (*SubscribeRequestPacket, error) {
	return &SubscribeRequestPacket{
		Header: *header,
	}, nil
}

// SubscribeReply
type SubscribeReplyPacket struct {
	Header PacketHeader
}

func NewSubscribeReplyPacket(requestNumber int) *SubscribeReplyPacket {
	return &SubscribeReplyPacket{
		Header: NewHeader(PacketTypeSubscribeReply, requestNumber),
	}
}

func (packet *SubscribeReplyPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeSubscribeReply(header *PacketHeader) (*SubscribeReplyPacket, error) {
	return &SubscribeReplyPacket{
		Header: *header,
	}, nil
}

// UnsubscribeRequest - get notified when sensor value is changed
type UnsubscribeRequestPacket struct {
	Header PacketHeader
}

func NewUnsubscribeRequestPacket(requestNumber int) *UnsubscribeRequestPacket {
	return &UnsubscribeRequestPacket{
		Header: NewHeader(PacketTypeUnsubscribeRequst, requestNumber),
	}
}

func (packet *UnsubscribeRequestPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeUnsubscribeRequest(header *PacketHeader) (*UnsubscribeRequestPacket, error) {
	return &UnsubscribeRequestPacket{
		Header: *header,
	}, nil
}

// UnsubscribeReply
type UnsubscribeReplyPacket struct {
	Header PacketHeader
}

func NewUnsubscribeReplyPacket(requestNumber int) *UnsubscribeReplyPacket {
	return &UnsubscribeReplyPacket{
		Header: NewHeader(PacketTypeUnsubscribeReply, requestNumber),
	}
}

func (packet *UnsubscribeReplyPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeUnsubscribeReply(header *PacketHeader) (*UnsubscribeReplyPacket, error) {
	return &UnsubscribeReplyPacket{
		Header: *header,
	}, nil
}

// StateChangedNotification
//  Sent to subscribers on sensor state change
type StateChangedNotificationPacket struct {
	Header       PacketHeader
	SensorNumber byte
	IsCovered    bool
	Version      uint32
	States       []bool
}

func NewStateChangedNotificationPacket(requestNumber int, sensorNumber byte, isCovered bool, version uint32, states []bool) *StateChangedNotificationPacket {
	return &StateChangedNotificationPacket{
		Header:       NewHeader(PacketTypeStateChangedNotification, requestNumber),
		SensorNumber: sensorNumber,
		IsCovered:    isCovered,
		Version:      version,
		States:       states,
	}
}

func (packet *StateChangedNotificationPacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	buffer.WriteByte(packet.SensorNumber)

	if packet.IsCovered {
		buffer.WriteByte(1)
	} else {
		buffer.WriteByte(0)
	}

	if err := binary.Write(buffer, binary.LittleEndian, &packet.Version); err != nil {
		panic(err)
	}

	buffer.WriteByte(byte(len(packet.States)))
	if err := binary.Write(buffer, binary.LittleEndian, packet.States); err != nil {
		panic(err)
	}

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeStateChangedNotification(header *PacketHeader) (*StateChangedNotificationPacket, error) {
	sensorNumber, err := packetReader.ReadByte()
	if err != nil {
		return nil, err
	}

	isCovered := false

	if isCoveredValue, err := packetReader.ReadByte(); err != nil {
		return nil, err
	} else if isCoveredValue != 0 {
		isCovered = true
	}

	var version uint32
	if err := binary.Read(packetReader, binary.LittleEndian, &version); err != nil {
		return nil, err
	}

	count, err := packetReader.ReadByte()
	if err != nil {
		return nil, err
	}

	states := make([]bool, count)
	if err := binary.Read(packetReader, binary.LittleEndian, &states); err != nil {
		return nil, err
	}

	return &StateChangedNotificationPacket{
		Header:       *header,
		SensorNumber: sensorNumber,
		IsCovered:    isCovered,
		Version:      version,
		States:       states,
	}, nil
}

type StateChangedAcknowledgePacket struct {
	Header PacketHeader
}

func NewStateChangedAcknowledgePacket(requestNumber int) *StateChangedAcknowledgePacket {
	return &StateChangedAcknowledgePacket{
		Header: NewHeader(PacketTypeStateChangedAcknowledge, requestNumber),
	}
}

func (packet *StateChangedAcknowledgePacket) Encode() []byte {
	buffer := bytes.NewBuffer(nil)
	packet.Header.EncodeTo(buffer)

	return buffer.Bytes()
}

func (packetReader TrainDetectorPacketReader) DecodeStateChangedAcknowledge(header *PacketHeader) (*StateChangedAcknowledgePacket, error) {
	return &StateChangedAcknowledgePacket{
		Header: *header,
	}, nil
}
