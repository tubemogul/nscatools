package nscatools

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
	"time"
)

type pktCases []struct {
	versionOut      int16
	crcOut          uint32
	timestampIn     uint32
	stateIn         int16
	stateOut        int16
	hostNameIn      string
	hostNameOut     string
	serviceIn       string
	serviceOut      string
	pluginOutputIn  string
	pluginOutputOut string
	ivIn            *InitPacket
	ivOut           *InitPacket
	passwordIn      []byte
	passwordOut     []byte
	encryptionIn    int
	encryptionOut   int
	rawBuffer       []byte
	cryptBuffer     []byte
	networkPacket   *bytes.Buffer
}

// this builds the input networkPacket field based on the other fields of the
// test case but only for the xor and None encryptions
func buildNetworkPacket(packets *pktCases) {
	for idx, pkt := range *packets {
		if pkt.encryptionIn != EncryptNone && pkt.encryptionIn != EncryptXOR {
			continue
		}
		buf := bytes.NewBuffer([]byte{})
		binary.Write(buf, binary.BigEndian, pkt.versionOut)
		buf.Write(make([]byte, 6))
		binary.Write(buf, binary.BigEndian, pkt.timestampIn)
		binary.Write(buf, binary.BigEndian, pkt.stateOut)
		tmp := make([]byte, 64)
		copy(tmp, pkt.hostNameOut)
		buf.Write(tmp)
		tmp = make([]byte, 128)
		copy(tmp, pkt.serviceOut)
		buf.Write(tmp)
		tmp = make([]byte, 4096)
		copy(tmp, pkt.pluginOutputOut)
		buf.Write(tmp)
		buf.Write(make([]byte, 2))

		b := buf.Bytes()
		crcdPacket := make([]byte, 4304)
		copy(crcdPacket, b[0:4])
		copy(crcdPacket[8:], b[8:])
		(*packets)[idx].crcOut = crc32.ChecksumIEEE(crcdPacket)
		binary.BigEndian.PutUint32(b[4:8], (*packets)[idx].crcOut)

		switch pkt.encryptionIn {
		case EncryptNone:
			pkt.networkPacket.Write(b)
		case EncryptXOR:
			ivSize := len(pkt.ivIn.Iv)
			pwdSize := len(pkt.passwordIn)
			for y := 0; y < len(b); y++ {
				b[y] ^= pkt.ivIn.Iv[y%ivSize] ^ pkt.passwordIn[y%pwdSize]
			}
			pkt.networkPacket.Write(b)
		}

	}
}

// We need to reinitialize the values every time as we change the byte arrays
// during the testing process
func getPktCases() *pktCases {
	pkt := pktCases{
		{
			3, 0, uint32(time.Now().Unix()), StateCritical, StateCritical, "MyHost", "MyHost",
			"MyService", "MyService", "My output", "My output",
			&InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())}, &InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())},
			[]byte("freebird"), []byte("freebird"),
			EncryptNone, EncryptNone,
			[]byte("breaking the law"),
			[]byte("breaking the law"),
			bytes.NewBuffer([]byte{}),
		},
		{
			3, 0, uint32(time.Now().Unix()), StateOK, StateOK, "localhost", "localhost",
			"dummy service", "dummy service", "Everything is fine", "Everything is fine",
			&InitPacket{Iv: []byte("welcome to the jungle"), Timestamp: uint32(time.Now().Unix())}, &InitPacket{Iv: []byte("welcome to the jungle"), Timestamp: uint32(time.Now().Unix())},
			[]byte("crash"), []byte("crash"),
			EncryptXOR, EncryptXOR,
			[]byte("sympathy for the devil"),
			[]byte{0x67, 0x6e, 0x60, 0x60, 0x66, 0x7a, 0x7f, 0x38, 0x27, 0x61, 0x2c, 0x74, 0x29, 0x62, 0x20, 0x6c, 0x27, 0x6b, 0x71, 0x72, 0x6f, 0x69},
			bytes.NewBuffer([]byte{}),
		},
		{
			3, 0, uint32(time.Now().Unix()), StateUnknown, StateUnknown, "127.0.0.1", "127.0.0.1",
			"bla", "bla", "Dunno", "Dunno",
			&InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())}, &InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())},
			[]byte("freebird"), []byte("freebird"),
			EncryptRC6, EncryptRC6,
			[]byte("breaking the law"),
			[]byte("breaking the law"),
			bytes.NewBuffer(make([]byte, 4304)),
		},
	}
	buildNetworkPacket(&pkt)
	return &pkt
}

func TestNewDataPacket(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)

		// Assuming it takes less than 5secs to generate a datapacket! :-D
		if pkt.Timestamp < tt.timestampIn || pkt.Timestamp > tt.timestampIn+5 {
			t.Error("Auto-generated timestamp not in the right time range")
		}

		if pkt.Version != 3 {
			t.Errorf("Expecting version: %d, got: %d\n", 3, pkt.Version)
		}
		if pkt.Crc != 0 {
			t.Errorf("Expecting crc: %d, got: %d\n", tt.crcOut, pkt.Crc)
		}
		if pkt.State != 3 {
			t.Errorf("Expecting state: %d, got: %d\n", 3, pkt.State)
		}
		if pkt.HostName != "" {
			t.Errorf("Expecting hostname: %s, got: %s\n", "", pkt.HostName)
		}
		if pkt.Service != "" {
			t.Errorf("Expecting service: %s, got: %s\n", "", pkt.Service)
		}
		if pkt.PluginOutput != "" {
			t.Errorf("Expecting plugin output: %s, got: %s\n", "", pkt.PluginOutput)
		}
		if !bytes.Equal(pkt.Ipkt.Iv, tt.ivOut.Iv) {
			t.Errorf("Expecting Iv: %s, got: %s\n", tt.ivOut.Iv, pkt.Ipkt.Iv)
		}
		if !bytes.Equal(pkt.Password, tt.passwordOut) {
			t.Errorf("Expecting password: %d, got: %d\n", tt.passwordOut, pkt.Password)
		}
		if pkt.Encryption != tt.encryptionOut {
			t.Errorf("Expecting encryption: %d, got: %d\n", tt.encryptionOut, pkt.Encryption)
		}
	}
}

func TestDataPacketXor(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		pkt.xor(tt.rawBuffer)
		// When not a xor encryption, the cryptBuffer is not encrypted so we revert
		// by doing a 2nd xor, checking the reversability at the same time
		if pkt.Encryption != 1 {
			pkt.xor(tt.rawBuffer)
		}
		if !bytes.Equal(tt.rawBuffer, tt.cryptBuffer) {
			t.Errorf("Expecting buffer: %s, got: %s\n", tt.cryptBuffer, tt.rawBuffer)
		}
	}
}

// Checks the error from the Encrypt/Decrypt function
func checkEncryptDecryptError(t *testing.T, pkt *DataPacket, err error) {
	if pkt.Encryption == EncryptRC6 || pkt.Encryption == EncryptMARS || pkt.Encryption == EncryptPANAMA || pkt.Encryption == EncryptIDEA {
		if err.Error() != "Unimplemented encryption algorithm" {
			t.Errorf("pkt.Encrypt returned: %s\n", err)
		} else {
			t.Logf("Note: RC6, MARS, PANAMA and IDEA were not implemented in the NSCA original server")
		}
	} else {
		t.Errorf("Packet encyption/decryption returned: %s for encryption: %d\n", err, pkt.Encryption)
	}
}

func TestDataPacketRead(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		if err := pkt.Read(tt.networkPacket); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}

		// We're only testing the Read transformation input -> attributes with Xor
		// and None as encryptions. The rest of the encryption processes are tested
		// directly in the tests for Encrypt and Decrypt methods
		if tt.encryptionIn != EncryptNone && tt.encryptionIn != EncryptXOR {
			t.Logf("Note: For the test of the Read method, only encryptions None and Xor output are tested")
			continue
		}

		if pkt.Version != tt.versionOut {
			t.Errorf("Expecting version: %d, got: %d\n", tt.versionOut, pkt.Version)
		}
		if pkt.Crc != tt.crcOut {
			t.Errorf("Expecting CRC: %d, got: %d\n", tt.crcOut, pkt.Crc)
		}
		if pkt.Timestamp != tt.timestampIn {
			t.Errorf("Expecting timestamp: %d, got: %d\n", tt.timestampIn, pkt.Timestamp)
		}
		if pkt.State != tt.stateOut {
			t.Errorf("Expecting state: %d, got: %d\n", tt.stateOut, pkt.State)
		}
		if pkt.HostName != tt.hostNameOut {
			t.Errorf("Expecting hostname: %s, got: %s\n", tt.hostNameOut, pkt.HostName)
		}
		if pkt.Service != tt.serviceOut {
			t.Errorf("Expecting state: %s, got: %s\n", tt.serviceOut, pkt.Service)
		}
		if pkt.PluginOutput != tt.pluginOutputOut {
			t.Errorf("Expecting plugin output: %s, got: %s\n", tt.pluginOutputOut, pkt.PluginOutput)
		}
	}
}

// Receiving a datapacket with the wrong size
func TestDataPacketReadWrongSize(t *testing.T) {
	pkt := NewDataPacket(0, []byte{0x00}, &InitPacket{})
	if err := pkt.Read(bytes.NewBuffer(make([]byte, 10))); err != nil {
		if !strings.Contains(err.Error(), "Dropping packet with invalid size") {
			checkEncryptDecryptError(t, pkt, err)
		}
	}
}

// Receiving a datapacket with the wrong crc32
func TestDataPacketReadWrongCrc32(t *testing.T) {
	pkt := NewDataPacket(0, []byte{0x00}, &InitPacket{})
	if err := pkt.Read(bytes.NewBuffer(make([]byte, 4304))); err != nil {
		if err.Error() != "Dropping packet with invalid CRC32 - possibly due to client using wrong password or crypto algorithm?" {
			checkEncryptDecryptError(t, pkt, err)
		}
	}
}

// Receiving a datapacket with the wrong timestamp difference
func TestDataPacketReadWrongTimestamp(t *testing.T) {
	pkt := NewDataPacket(0, []byte{0x00}, &InitPacket{})
	pktData := make([]byte, 4304)
	binary.BigEndian.PutUint32(pktData[8:12], uint32(time.Now().Unix()+100))
	binary.BigEndian.PutUint32(pktData[4:8], pkt.CalculateCrc(pktData))
	if err := pkt.Read(bytes.NewBuffer(pktData)); err != nil {
		if err.Error() != "Dropping packet with stale timestamp - Max age difference is 30 seconds" {
			checkEncryptDecryptError(t, pkt, err)
		}
	}
}

func BenchmarkDataPacketRead(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pkt := NewDataPacket(0, []byte{}, &InitPacket{Iv: []byte("aerosmith"), Timestamp: uint32(time.Now().Unix())})
		pktData := make([]byte, 4304)
		copy(pktData, []byte{0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x58, 0x66, 0xfa, 0xeb, 0x0, 0x2, 0x4d, 0x79, 0x48, 0x6f, 0x73, 0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x79, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x79, 0x20, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74})
		binary.BigEndian.PutUint32(pktData[8:12], uint32(time.Now().Unix()))
		binary.BigEndian.PutUint32(pktData[4:8], pkt.CalculateCrc(pktData))
		networkPacket := bytes.NewBuffer(pktData)
		if err := pkt.Read(networkPacket); err != nil {
			b.Errorf("DataPacket.Read benchmark call returned: %s\n", err)
		}
	}
}

func TestDataPacketWrite(t *testing.T) {
	cases := getPktCases()
	for _, tt := range *cases {
		b := new(bytes.Buffer)
		pkt := NewDataPacket(tt.encryptionIn, tt.passwordIn, tt.ivIn)
		pkt.Timestamp = tt.timestampIn
		pkt.State = tt.stateIn
		pkt.HostName = tt.hostNameIn
		pkt.Service = tt.serviceIn
		pkt.PluginOutput = tt.pluginOutputIn

		if err := pkt.Write(b); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}
		// We're only testing the Write method with Xor
		// and None as encryptions. The rest of the encryption processes are tested
		// directly in the tests for Encrypt and Decrypt methods
		if tt.encryptionIn != EncryptNone && tt.encryptionIn != EncryptXOR {
			t.Logf("Note: For the test of the Read method, only encryptions None and Xor output are tested")
			continue
		}

		if !bytes.Equal(b.Bytes(), tt.networkPacket.Bytes()) {
			t.Errorf("expecting : %v, got: %v", tt.networkPacket.Bytes(), b.Bytes())
		}
	}
}

// Reusing the writerMock created in initpacket_test.go
func TestDataPacketWriteInconsistentResult(t *testing.T) {
	m := writerMock{}
	pkt := NewDataPacket(0, []byte{}, &InitPacket{})
	if err := pkt.Write(&m); err.Error() != "0 bytes written, expecting 4304. Error: %!s(<nil>)" {
		t.Errorf("DataPacket.Write() should signal inconsistent number of bytes but outputed: %s", err)
	}
}

// Testing the encryption algorithms themselves
type encryptionCases []struct {
	password     []byte
	iv           *InitPacket
	encryption   int
	message      []byte
	encryptedMsg []byte
}

func getEncCases() *encryptionCases {
	ipkt := InitPacket{Iv: make([]byte, 128), Timestamp: 1483333965}
	copy(ipkt.Iv, "abcdefghijklnmopqrstuvwxyzabcdefghijklnmopqrstuvwxyzabcdefghijklnmopqrstuvwxyzabcdefghijklnmopqrstuvwxyzabcdefghijklnmopqrstuvw")
	pwd := []byte("this is a simple password... Maybe a little too long but that's just to avoid too short keys.")
	return &encryptionCases{
		{pwd, &ipkt, EncryptNone, []byte("The full content of my message"), []byte("The full content of my message")},
		{pwd, &ipkt, EncryptXOR, []byte("The full content of my message"), []byte{0x41, 0x62, 0x6f, 0x37, 0x23, 0x7a, 0x78, 0x24, 0x28, 0x29, 0x77, 0x6b, 0x77, 0x78, 0x6d, 0x61, 0x71, 0x6d, 0x74, 0x27, 0x6b, 0x78, 0x38, 0x67, 0x78, 0x27, 0x3c, 0x2d, 0x24, 0x4c}},
		{pwd, &ipkt, EncryptDES, []byte("The full content of my message"), []byte{0x29, 0xc5, 0x2d, 0xe0, 0xf5, 0x9e, 0xa3, 0x9b, 0x41, 0xa5, 0x27, 0x6e, 0x9b, 0x9b, 0xe1, 0x92, 0x7b, 0xa0, 0x6c, 0xb6, 0x9c, 0xdc, 0xb7, 0xd8, 0x7d, 0x6, 0xb3, 0xe2, 0x94, 0xac}},
		{pwd, &ipkt, Encrypt3DES, []byte("The full content of my message"), []byte{0x5b, 0x54, 0x91, 0xa0, 0xea, 0x5f, 0x7b, 0x17, 0xfe, 0x7, 0xde, 0xdf, 0x5f, 0x7, 0x3a, 0xbf, 0x59, 0xea, 0x4a, 0x7e, 0xa7, 0xb7, 0x42, 0x4d, 0xa5, 0x45, 0x31, 0x51, 0x9b, 0x1d}},
		{pwd, &ipkt, EncryptCAST128, []byte("The full content of my message"), []byte{0x58, 0x5e, 0xd4, 0xe5, 0x27, 0x22, 0x2, 0xfb, 0x37, 0x51, 0x91, 0x4a, 0x5b, 0x21, 0x25, 0x3d, 0x6c, 0xc6, 0x3e, 0x40, 0x58, 0xa0, 0x44, 0xc, 0x0, 0x4a, 0x9d, 0xd6, 0x1d, 0xc}},
		{pwd, &ipkt, EncryptCAST256, []byte("The full content of my message"), []byte{0x1f, 0xe1, 0xf7, 0x23, 0xcb, 0x33, 0x9c, 0xfb, 0x29, 0x24, 0xae, 0xbd, 0x1f, 0x92, 0x76, 0xb6, 0x1e, 0x9b, 0x94, 0x4, 0xbc, 0x5d, 0x89, 0xf6, 0x14, 0xc6, 0x1a, 0x76, 0x5e, 0x2b}},
		{pwd, &ipkt, EncryptXTEA, []byte("The full content of my message"), []byte{0x9e, 0xa9, 0xec, 0xc7, 0xe5, 0xf, 0xa6, 0x2d, 0x1a, 0x61, 0x37, 0xea, 0x94, 0x4a, 0xf9, 0x83, 0x80, 0x26, 0x16, 0x61, 0x59, 0xca, 0xe, 0xbd, 0x6, 0x7d, 0x9d, 0xa4, 0xec, 0x9b}},
		//		{pwd, &ipkt, Encrypt3WAY, []byte("The full content of my message"), []byte{0x54, 0x68, 0x65, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x79, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}},
		{pwd, &ipkt, EncryptBLOWFISH, []byte("The full content of my message"), []byte{0xef, 0x57, 0xf, 0xf5, 0xef, 0x28, 0x5b, 0xd2, 0x43, 0xc4, 0x62, 0xa3, 0x11, 0xb5, 0x6f, 0xe7, 0x79, 0x1e, 0xb7, 0xf5, 0xde, 0xd1, 0x8, 0x35, 0x7d, 0xda, 0xdb, 0x61, 0xa6, 0x1b}},
		{pwd, &ipkt, EncryptTWOFISH, []byte("The full content of my message"), []byte{0x66, 0xb2, 0xe3, 0x14, 0x24, 0x82, 0x4c, 0x46, 0x5, 0xe0, 0x3d, 0xb9, 0xb7, 0xbd, 0x86, 0xfe, 0x69, 0x82, 0xde, 0x92, 0x24, 0x3b, 0x59, 0x6a, 0xce, 0xdb, 0x1d, 0x36, 0x83, 0x79}},
		{pwd, &ipkt, EncryptLOKI97, []byte("The full content of my message"), []byte{0x45, 0x1f, 0x2d, 0x9f, 0xc, 0x3, 0xc2, 0xa7, 0xa8, 0xa, 0x7, 0xe9, 0xc, 0xa2, 0x30, 0xdc, 0xef, 0x89, 0x5c, 0xdb, 0xcb, 0xce, 0x48, 0x55, 0x9f, 0xf8, 0x9e, 0xec, 0xb5, 0x37}},
		{pwd, &ipkt, EncryptRC2, []byte("The full content of my message"), []byte{0xed, 0x8b, 0x64, 0xab, 0x70, 0x82, 0x43, 0x10, 0x7, 0x97, 0x2c, 0x74, 0x25, 0x2f, 0x51, 0x76, 0x23, 0x78, 0x77, 0xa8, 0xcf, 0xe, 0xcb, 0xff, 0x80, 0xb1, 0x81, 0x53, 0xe4, 0x98}},
		//		{pwd, &ipkt, EncryptARCFOUR, []byte("The full content of my message"), []byte{0x54, 0x68, 0x65, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x79, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}},
		{pwd, &ipkt, EncryptRIJNDAEL128, []byte("The full content of my message"), []byte{0xf2, 0x2a, 0x37, 0xc3, 0x1, 0x73, 0x4e, 0xa0, 0x94, 0x7d, 0xec, 0xdd, 0x5b, 0x16, 0xce, 0x99, 0x2f, 0x42, 0x25, 0x9d, 0xd8, 0xb8, 0x99, 0x2b, 0xd6, 0x59, 0x19, 0x7a, 0x2, 0x74}},
		{pwd, &ipkt, EncryptRIJNDAEL192, []byte("The full content of my message"), []byte{0x9, 0x44, 0xe, 0xd4, 0xdc, 0x55, 0x26, 0x51, 0xde, 0xea, 0x30, 0x61, 0xb3, 0x6b, 0x36, 0xe6, 0x42, 0x8f, 0x3b, 0xcd, 0x4, 0xba, 0x2a, 0xe5, 0xc8, 0x57, 0x3f, 0xcf, 0x98, 0x96}},
		{pwd, &ipkt, EncryptRIJNDAEL256, []byte("The full content of my message"), []byte{0x6e, 0x6c, 0x9f, 0xbe, 0xa2, 0xc4, 0x5a, 0x4d, 0xad, 0x76, 0xf1, 0x92, 0x15, 0x92, 0xd, 0x7b, 0x68, 0xdf, 0x46, 0xe5, 0xe7, 0x3b, 0xed, 0x98, 0x92, 0xc7, 0xdd, 0xfc, 0x1c, 0x3a}},
		//		{pwd, &ipkt, EncryptWAKE, []byte("The full content of my message"), []byte{0x54, 0x68, 0x65, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x79, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}},
		{pwd, &ipkt, EncryptSERPENT, []byte("The full content of my message"), []byte{0xf4, 0x5c, 0xb, 0xb0, 0x3b, 0x98, 0xdb, 0x69, 0x1c, 0xe6, 0xc4, 0x3c, 0xcc, 0xfd, 0x25, 0x49, 0x20, 0xf8, 0x9c, 0x92, 0xfc, 0x5, 0x92, 0xed, 0x98, 0x10, 0x60, 0xd6, 0x92, 0xca}},
		//		{pwd, &ipkt, EncryptENIGMA, []byte("The full content of my message"), []byte{0x54, 0x68, 0x65, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x79, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}},
		{pwd, &ipkt, EncryptGOST, []byte("The full content of my message"), []byte{0x45, 0x28, 0x98, 0xe0, 0xe0, 0x35, 0x2f, 0xa2, 0x60, 0x6b, 0xc6, 0xe1, 0x4a, 0xd6, 0x4c, 0x2d, 0x22, 0x2f, 0xcb, 0x76, 0x5f, 0x92, 0x98, 0xd3, 0x54, 0xb3, 0xbd, 0xc3, 0x72, 0x61}},
		//		{pwd, &ipkt, EncryptSAFER64, []byte("The full content of my message"), []byte{0x54, 0x68, 0x65, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x79, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}},
		//		{pwd, &ipkt, EncryptSAFER128, []byte("The full content of my message"), []byte{0x54, 0x68, 0x65, 0x20, 0x66, 0x75, 0x6c, 0x6c, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x79, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65}},
		{pwd, &ipkt, EncryptSAFERPLUS, []byte("The full content of my message"), []byte{0x61, 0x1f, 0xd, 0x8b, 0x9, 0xe8, 0xbb, 0x1e, 0xd9, 0x43, 0xbf, 0x58, 0x63, 0x8f, 0xa4, 0x78, 0x3e, 0x7c, 0xa8, 0xb4, 0x9d, 0xc7, 0x1b, 0xee, 0x84, 0x52, 0x39, 0xa3, 0x42, 0x25}},
	}
}

func TestDataPacketEncrypt(t *testing.T) {
	cases := getEncCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryption, tt.password, tt.iv)
		if err := pkt.Encrypt(tt.message); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}
		if !bytes.Equal(tt.message, tt.encryptedMsg) {
			t.Errorf("Expecting buffer: %#v\n\tgot: %#v\n\tfor encryption: %d\n", tt.encryptedMsg, tt.message, tt.encryption)
		}
	}
}

func TestDataPacketDecrypt(t *testing.T) {
	cases := getEncCases()
	for _, tt := range *cases {
		pkt := NewDataPacket(tt.encryption, tt.password, tt.iv)
		if err := pkt.Decrypt(tt.encryptedMsg); err != nil {
			checkEncryptDecryptError(t, pkt, err)
		}
		if !bytes.Equal(tt.encryptedMsg, tt.message) {
			t.Errorf("Expecting buffer: %#v\n\tgot: %#v\n\tfor encryption: %d\n", tt.message, tt.encryptedMsg, tt.encryption)
		}
	}
}
