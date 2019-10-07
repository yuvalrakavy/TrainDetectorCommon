package networkProtocol

import (
	"bytes"
	"encoding/binary"
)

type TrainDetectorPacket []byte
type TrainDetectorPacketReader struct {
	reader *bytes.Reader
}

func (packetReader TrainDetectorPacketReader) Read(b []byte) (int, error) {
	return packetReader.reader.Read(b)
}

func (packetReader TrainDetectorPacketReader) ReadByte() (byte, error) {
	return packetReader.reader.ReadByte()
}

func (r TrainDetectorPacketReader) Header() (PacketHeader, error) {
	var header PacketHeader

	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return PacketHeader{}, err
	}

	return header, nil
}

func (header PacketHeader) IsValid() bool {
	return header.PacketType == ^header.PacketTypeCompliment
}

func (packet TrainDetectorPacket) Reader() TrainDetectorPacketReader {
	return TrainDetectorPacketReader{bytes.NewReader(packet)}
}

func (packet TrainDetectorPacket) Header() PacketHeader {
	r := packet.Reader()
	header, err := r.Header()

	if err != nil {
		panic("Invalid header")
	}

	return header
}

func (packet TrainDetectorPacket) IsReply() bool {
	return (packet.Header().PacketType & PacketClassReply) != 0
}

func (packet TrainDetectorPacket) GetRequestNumber() int {
	return packet.Header().RequestNumber()
}
