package main

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"log"
	"time"

	"github.com/pion/stun/v2"
)

func fingerprint(b []byte) uint32 {
	crc := crc32.ChecksumIEEE(b)
	return crc ^ fingerprintXORValue // XOR
}

func checkFingerprint(got, expected uint32) error {
	if got == expected {
		return nil
	}
	return errors.New("mismatch")
}

func checkFingerPrint(m *stun.Message) error {
	b, err := m.Get(stun.AttrFingerprint)
	if err != nil {
		return err
	}
	if err = stun.CheckSize(stun.AttrFingerprint, len(b), fingerprintSize); err != nil {
		return err
	}
	val := binary.BigEndian.Uint32(b)
	log.Println("Value", val)
	attrStart := len(m.Raw) - (fingerprintSize + 4)
	expected := fingerprint(m.Raw[:attrStart])
	log.Println("Expected", expected)
	return checkFingerprint(val, expected)
}

const (
	fingerprintXORValue uint32 = 0x5354554e //nolint:staticcheck
	fingerprintSize            = 4          // 32 bit
)

func main() {
	msg, err := stun.Build(stun.BindingRequest,
		stun.NewUsername("username:password"),
        stun.NewShortTermIntegrity("test"),
		stun.Fingerprint,
	) // stun.TransactionID,
	// stun.Fingerprint,

	err = checkFingerPrint(msg)
	if err != nil {
		panic(err)
	}

	// attr, _ := msg.Attributes.Get(stun.AttrUsername)
	// log.Println(attr.Length)

	msg.Encode()
	// log.Println(len(msg.Raw))

	log.Println(msg.Raw)
	log.Println("Length", msg.Length)

	// Example usage
	// responseHeader, err := ResponseHeader(MethodChannelBind, ClassErrorResponse)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// 	return
	// }
	// fmt.Printf("Response Header: 0x%x\n", responseHeader.Value())
	//
	// responseHeaderSecond, err := ResponseHeader(MethodBinding, ClassErrorResponse)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// 	return
	// }
	//
	// responseHeaderSecond.ReadValue(responseHeader.Value())
	//
	// b := make([]byte, 2)
	// binary.BigEndian.PutUint16(b, responseHeader.Value())
	// fmt.Println(b)
}
