package nscatools

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"time"
)

// DataPacket stores the data received for the client-server communication
type DataPacket struct {
	Version      int16
	Crc          uint32
	Timestamp    uint32
	State        int16
	HostName     string
	Service      string
	PluginOutput string
	Ipkt         *InitPacket
	Password     []byte
	Encryption   int
}

// NewDataPacket initializes a new blank data packet
func NewDataPacket(encryption int, password []byte, ipkt *InitPacket) *DataPacket {
	packet := DataPacket{
		Version:      3,
		Crc:          0,
		Timestamp:    uint32(time.Now().Unix()),
		State:        StateUnknown,
		HostName:     "",
		Service:      "",
		PluginOutput: "",
		Ipkt:         ipkt,
		Password:     password,
		Encryption:   encryption,
	}
	return &packet
}

// CalculateCrc returns the Crc of a packet ready to be sent over the network,
// ignoring the Crc data part of it as it's done in the original nsca code
func (p *DataPacket) CalculateCrc(buffer []byte) uint32 {
	crcdPacket := make([]byte, len(buffer))
	copy(crcdPacket, buffer[0:4])
	copy(crcdPacket[8:], buffer[8:])
	return crc32.ChecksumIEEE(crcdPacket)
}

// Read gets the data packet and populates the attributes of the DataPacket
// according. When encountering an error, it returns the error and don't process
// further.
func (p *DataPacket) Read(conn io.Reader) error {
	// We need to read the full packet 1st to check the crc and decrypt it too
	fullPacket, err := ioutil.ReadAll(conn)
	if err != nil {
		return err
	}
	
	if len(fullPacket) != ShortPacketLength && len(fullPacket) != LongPacketLength {
		return fmt.Errorf("Dropping packet with invalid size: %d", len(fullPacket))
	}
	
	if err := p.Decrypt(fullPacket); err != nil {
		return err
	}

	p.Crc = binary.BigEndian.Uint32(fullPacket[4:8])
	if crc32 := p.CalculateCrc(fullPacket); p.Crc != crc32 {
		return fmt.Errorf("Dropping packet with invalid CRC32 - possibly due to client using wrong password or crypto algorithm?")
	}

	p.Timestamp = binary.BigEndian.Uint32(fullPacket[8:12])
	// MaxPacketAge <= 0 means that we don't check it
	if MaxPacketAge > 0 {
		if p.Timestamp > (p.Ipkt.Timestamp+MaxPacketAge) || p.Timestamp < (p.Ipkt.Timestamp-MaxPacketAge) {
			return fmt.Errorf("Dropping packet with stale timestamp - Max age difference is %d seconds", MaxPacketAge)
		}
	}

	sep := []byte("\x00") // sep is used to extract only the useful string
	p.Version = int16(binary.BigEndian.Uint16(fullPacket[0:2]))
	p.State = int16(binary.BigEndian.Uint16(fullPacket[12:14]))
	p.HostName = string(bytes.Split(fullPacket[14:78], sep)[0])
	p.Service = string(bytes.Split(fullPacket[78:206], sep)[0])
	p.PluginOutput = string(bytes.Split(fullPacket[206:], sep)[0])

	return nil
}

// Write generates the buffer to write to the writer based on the populated
// fields of the DataPacket instance encrypts it if needed and send it to the
// writer.
// When encountering an error, it returns the error and don't process
// further.
func (p *DataPacket) Write(w io.Writer) error {

	// Build network packet
	packet := new(bytes.Buffer)
	binary.Write(packet, binary.BigEndian, p.Version)
	binary.Write(packet, binary.BigEndian, make([]byte, 6))
	binary.Write(packet, binary.BigEndian, p.Timestamp)
	binary.Write(packet, binary.BigEndian, p.State)
	h := make([]byte, 64)
	copy(h, p.HostName)
	binary.Write(packet, binary.BigEndian, h)
	s := make([]byte, 128)
	copy(s, p.Service)
	binary.Write(packet, binary.BigEndian, s)
	o := make([]byte, 64)
	copy(o, p.PluginOutput)
	binary.Write(packet, binary.BigEndian, o)
	binary.Write(packet, binary.BigEndian, make([]byte, 2))

	buf := make([]byte, LongPacketLength)
	copy(buf, packet.Bytes())

	// Calculate the Crc
	binary.BigEndian.PutUint32(buf[4:8], p.CalculateCrc(buf))

	// Encrypt
	if err := p.Encrypt(buf); err != nil {
		return err
	}

	// Write + consistency check
	if n, err := w.Write(buf); err != nil || n != len(buf) {
		return fmt.Errorf("%d bytes written, expecting %d. Error: %s", n, len(buf), err)
	}

	return nil
}

// Performs a XOR operation on a buffer using the initialization vector and the
// password.
func (p *DataPacket) xor(buffer []byte) {
	bufferSize := len(buffer)
	ivSize := len(p.Ipkt.Iv)
	pwdSize := len(p.Password)
	// Rotating over the initialization vector of the connection and the password
	for y := 0; y < bufferSize; y++ {
		buffer[y] ^= p.Ipkt.Iv[y%ivSize] ^ p.Password[y%pwdSize]
	}
}

// setAlgo translates the encryption to an mcrypt-understandable from algorithm name
func (p *DataPacket) setAlgo() string {
	var algo string
	switch p.Encryption {
	case EncryptDES:
		algo = "des"
	case Encrypt3DES:
		algo = "tripledes"
	case EncryptCAST128:
		algo = "cast-128"
	case EncryptCAST256:
		algo = "cast-256"
	case EncryptXTEA:
		algo = "xtea"
	case Encrypt3WAY:
		algo = "threeway"
	case EncryptBLOWFISH:
		algo = "blowfish"
	case EncryptTWOFISH:
		algo = "twofish"
	case EncryptLOKI97:
		algo = "loki97"
	case EncryptRC2:
		algo = "rc2"
	case EncryptARCFOUR:
		algo = "arcfour"
	case EncryptRIJNDAEL128:
		algo = "rijndael-128"
	case EncryptRIJNDAEL192:
		algo = "rijndael-192"
	case EncryptRIJNDAEL256:
		algo = "rijndael-256"
	case EncryptWAKE:
		algo = "wake"
	case EncryptSERPENT:
		algo = "serpent"
	case EncryptENIGMA:
		algo = "enigma"
	case EncryptGOST:
		algo = "gost"
	case EncryptSAFER64:
		algo = "safer-sk64"
	case EncryptSAFER128:
		algo = "safer-sk128"
	case EncryptSAFERPLUS:
		algo = "saferplus"
	default:
		algo = "Unknown"
	}
	return algo
}

// Decrypt decrypts a buffer
func (p *DataPacket) Decrypt(buffer []byte) error {
	var (
		algo string
		err  error
	)

	switch p.Encryption {
	case EncryptNone: // Just don't do anything
	case EncryptXOR:
		p.xor(buffer)
	case EncryptIDEA: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRC6: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptMARS: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptPANAMA: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	default:
		algo = p.setAlgo()
		if algo == "Unknown" {
			err = fmt.Errorf("%d is an unrecognized encryption integer", p.Encryption)
		}
	}
	if err != nil {
		return err
	}
	if algo != "" {
		err = MCrypt(algo, buffer, p.Password, p.Ipkt.Iv, true)
	}
	return err
}

// Encrypt encrypts a buffer
func (p *DataPacket) Encrypt(buffer []byte) error {
	var (
		algo string
		err  error
	)

	switch p.Encryption {
	case EncryptNone:
	case EncryptXOR:
		p.xor(buffer)
	case EncryptIDEA: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptRC6: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptMARS: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	case EncryptPANAMA: // Unsupported in standard NSCA
		err = fmt.Errorf("Unimplemented encryption algorithm")
	default:
		algo = p.setAlgo()
		if algo == "Unknown" {
			err = fmt.Errorf("%d is an unrecognized encryption integer", p.Encryption)
		}
	}
	if err != nil {
		return err
	}
	if algo != "" {
		err = MCrypt(algo, buffer, p.Password, p.Ipkt.Iv, false)
	}
	return err
}

// Encrypt* are the encryptions supported by the standard NSCA configuration
const (
	EncryptNone        = iota // no encryption
	EncryptXOR                // Simple XOR  (No security, just obfuscation, but very fast)
	EncryptDES                // DES
	Encrypt3DES               // 3DES or Triple DES
	EncryptCAST128            // CAST-128
	EncryptCAST256            // CAST-256
	EncryptXTEA               // xTEA
	Encrypt3WAY               // 3-WAY
	EncryptBLOWFISH           // SKIPJACK
	EncryptTWOFISH            // TWOFISH
	EncryptLOKI97             // LOKI97
	EncryptRC2                // RC2
	EncryptARCFOUR            // RC4
	EncryptRC6                // RC6 - Unsupported in standard NSCA
	EncryptRIJNDAEL128        // AES-128
	EncryptRIJNDAEL192        // AES-192
	EncryptRIJNDAEL256        // AES-256
	EncryptMARS               // MARS - Unsupported in standard NSCA
	EncryptPANAMA             // PANAMA - Unsupported in standard NSCA
	EncryptWAKE               // WAKE
	EncryptSERPENT            // SERPENT
	EncryptIDEA               // IDEA - Unsupported in standard NSCA
	EncryptENIGMA             // ENIGMA (Unix crypt)
	EncryptGOST               // GOST
	EncryptSAFER64            // SAFER-sk64
	EncryptSAFER128           // SAFER-sk128
	EncryptSAFERPLUS          // SAFER+
)

// State* are the states understood by NSCA
const (
	StateOK = iota
	StateWarning
	StateCritical
	StateUnknown
)

// MaxPacketAge is the number of seconds difference allowed between the
// initialization packet epoch and the epoch of the data packet received
const MaxPacketAge = 30

const ShortPacketLength = 720
const LongPacketLength = 4304
