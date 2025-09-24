// SPDX-FileCopyrightText: 2024 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"

	"github.com/omec-project/n3iwf/ike/message"
	ikeCrypto "github.com/omec-project/n3iwf/ike/security/IKECrypto"
	"github.com/omec-project/n3iwf/ike/security/dh"
	"github.com/omec-project/n3iwf/ike/security/encr"
	"github.com/omec-project/n3iwf/ike/security/esn"
	"github.com/omec-project/n3iwf/ike/security/integ"
	"github.com/omec-project/n3iwf/ike/security/prf"
	"github.com/omec-project/n3iwf/logger"
)

// General data
var (
	randomNumberMaximum big.Int
	randomNumberMinimum big.Int
)

func init() {
	randomNumberMaximum.SetString(strings.Repeat("F", 512), 16)
	randomNumberMinimum.SetString(strings.Repeat("F", 32), 16)
}

// GenerateRandomNumber returns a random big.Int between randomNumberMinimum and randomNumberMaximum
func GenerateRandomNumber() (*big.Int, error) {
	for {
		number, err := rand.Int(rand.Reader, &randomNumberMaximum)
		if err != nil {
			logger.IKELog.Errorf("error occurs when generate random number: %+v", err)
			return nil, fmt.Errorf("error occurs when generate random number: %+v", err)
		}
		if number.Cmp(&randomNumberMinimum) == 1 {
			return number, nil
		}
	}
}

// GenerateRandomUint8 returns a random uint8 value
func GenerateRandomUint8() (uint8, error) {
	number := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, number); err != nil {
		logger.IKELog.Errorf("read random failed: %+v", err)
		return 0, fmt.Errorf("read random failed: %+v", err)
	}
	return number[0], nil
}

// concatenateNonceAndSPI concatenates nonce and both SPIs into a single byte slice
func concatenateNonceAndSPI(nonce []byte, spiInitiator, spiResponder uint64) []byte {
	buf := make([]byte, len(nonce)+16)
	copy(buf, nonce)
	binary.BigEndian.PutUint64(buf[len(nonce):], spiInitiator)
	binary.BigEndian.PutUint64(buf[len(nonce)+8:], spiResponder)
	return buf
}

// IKESAKey holds IKE SA keying material and algorithms
type IKESAKey struct {
	// IKE SA transform types
	DhInfo    dh.DHType
	EncrInfo  encr.ENCRType
	IntegInfo integ.INTEGType
	PrfInfo   prf.PRFType

	// Security objects
	Prf_d   hash.Hash           // used to derive key for child sa
	Integ_i hash.Hash           // used by initiator for integrity checking
	Integ_r hash.Hash           // used by responder for integrity checking
	Encr_i  ikeCrypto.IKECrypto // used by initiator for encrypting
	Encr_r  ikeCrypto.IKECrypto // used by responder for encrypting
	Prf_i   hash.Hash           // used by initiator for IKE authentication
	Prf_r   hash.Hash           // used by responder for IKE authentication

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication
}

func (ikesaKey *IKESAKey) String() string {
	return fmt.Sprintf(`\nEncryption Algorithm: %d\nSK_ei: %s\nSK_er: %s\nIntegrity Algorithm: %d\nSK_ai: %s\nSK_ar: %s\nSK_pi: %s\nSK_pr: %s\nSK_d : %s\n`,
		ikesaKey.EncrInfo.TransformID(),
		hex.EncodeToString(ikesaKey.SK_ei),
		hex.EncodeToString(ikesaKey.SK_er),
		ikesaKey.IntegInfo.TransformID(),
		hex.EncodeToString(ikesaKey.SK_ai),
		hex.EncodeToString(ikesaKey.SK_ar),
		hex.EncodeToString(ikesaKey.SK_pi),
		hex.EncodeToString(ikesaKey.SK_pr),
		hex.EncodeToString(ikesaKey.SK_d),
	)
}

// ToProposal converts IKESAKey to a message.Proposal
func (ikesaKey *IKESAKey) ToProposal() (*message.Proposal, error) {
	p := new(message.Proposal)
	p.ProtocolID = message.TypeIKE
	p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(ikesaKey.DhInfo))
	p.PseudorandomFunction = append(p.PseudorandomFunction, prf.ToTransform(ikesaKey.PrfInfo))
	encrTranform, err := encr.ToTransform(ikesaKey.EncrInfo)
	if err != nil {
		return nil, fmt.Errorf("IKESAKey ToProposal: %w", err)
	}
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encrTranform)
	p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransform(ikesaKey.IntegInfo))
	return p, nil
}

// return IKESAKey and local public value
func NewIKESAKey(
	proposal *message.Proposal,
	keyExchangeData, concatenatedNonce []byte,
	initiatorSPI, responderSPI uint64,
) (*IKESAKey, []byte, error) {
	if proposal == nil {
		return nil, nil, fmt.Errorf("proposal is nil")
	}
	if len(proposal.DiffieHellmanGroup) == 0 || len(proposal.EncryptionAlgorithm) == 0 || len(proposal.IntegrityAlgorithm) == 0 || len(proposal.PseudorandomFunction) == 0 {
		return nil, nil, fmt.Errorf("proposal missing required transforms")
	}

	ikesaKey := &IKESAKey{
		DhInfo:    dh.DecodeTransform(proposal.DiffieHellmanGroup[0]),
		EncrInfo:  encr.DecodeTransform(proposal.EncryptionAlgorithm[0]),
		IntegInfo: integ.DecodeTransform(proposal.IntegrityAlgorithm[0]),
		PrfInfo:   prf.DecodeTransform(proposal.PseudorandomFunction[0]),
	}
	if ikesaKey.DhInfo == nil || ikesaKey.EncrInfo == nil || ikesaKey.IntegInfo == nil || ikesaKey.PrfInfo == nil {
		return nil, nil, fmt.Errorf("unsupported transform in proposal")
	}

	localPublicValue, sharedKeyData, err := CalculateDiffieHellmanMaterials(ikesaKey, keyExchangeData)
	if err != nil {
		return nil, nil, fmt.Errorf("NewIKESAKey: %w", err)
	}
	if err := ikesaKey.GenerateKeyForIKESA(concatenatedNonce, sharedKeyData, initiatorSPI, responderSPI); err != nil {
		return nil, nil, fmt.Errorf("NewIKESAKey: %w", err)
	}
	return ikesaKey, localPublicValue, nil
}

// CalculateDiffieHellmanMaterials generates secret and calculates Diffie-Hellman public key exchange material
func CalculateDiffieHellmanMaterials(
	ikesaKey *IKESAKey,
	peerPublicValue []byte,
) ([]byte, []byte, error) {
	secret, err := GenerateRandomNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("CalculateDiffieHellmanMaterials(): %w", err)
	}
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	return ikesaKey.DhInfo.GetPublicValue(secret), ikesaKey.DhInfo.GetSharedKey(secret, peerPublicValueBig), nil
}

// GenerateKeyForIKESA derives all IKE SA keys as defined in RFC7296
func (ikesaKey *IKESAKey) GenerateKeyForIKESA(
	concatenatedNonce, diffieHellmanSharedKey []byte,
	initiatorSPI, responderSPI uint64,
) error {
	// Check parameters
	if ikesaKey == nil {
		logger.IKELog.Errorf("IKE SA is nil")
		return fmt.Errorf("IKE SA is nil")
	}

	// Check if the context contain needed data
	if ikesaKey.EncrInfo == nil {
		logger.IKELog.Errorf("no encryption algorithm specified")
		return fmt.Errorf("no encryption algorithm specified")
	}
	if ikesaKey.IntegInfo == nil {
		logger.IKELog.Errorf("no integrity algorithm specified")
		return fmt.Errorf("no integrity algorithm specified")
	}
	if ikesaKey.PrfInfo == nil {
		logger.IKELog.Errorf("no pseudorandom function specified")
		return fmt.Errorf("no pseudorandom function specified")
	}
	if ikesaKey.DhInfo == nil {
		logger.IKELog.Errorf("no Diffie-hellman group algorithm specified")
		return fmt.Errorf("no Diffie-hellman group algorithm specified")
	}

	if len(concatenatedNonce) == 0 {
		logger.IKELog.Errorf("no concatenated nonce data")
		return fmt.Errorf("no concatenated nonce data")
	}
	if len(diffieHellmanSharedKey) == 0 {
		logger.IKELog.Errorf("no Diffie-Hellman shared key")
		return fmt.Errorf("no Diffie-Hellman shared key")
	}

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int

	length_SK_d = ikesaKey.PrfInfo.GetKeyLength()
	length_SK_ai = ikesaKey.IntegInfo.GetKeyLength()
	length_SK_ar = length_SK_ai
	length_SK_ei = ikesaKey.EncrInfo.GetKeyLength()
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d

	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4

	prf := ikesaKey.PrfInfo.Init(concatenatedNonce)
	if _, err := prf.Write(diffieHellmanSharedKey); err != nil {
		return err
	}

	skeyseed := prf.Sum(nil)
	seed := concatenateNonceAndSPI(concatenatedNonce, initiatorSPI, responderSPI)

	keyStream := prfPlus(ikesaKey.PrfInfo.Init(skeyseed), seed, totalKeyLength)
	if keyStream == nil {
		logger.IKELog.Errorf("error occurred in PrfPlus")
		return fmt.Errorf("error occurred in PrfPlus")
	}

	// Assign keys into context
	ikesaKey.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	ikesaKey.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	ikesaKey.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	ikesaKey.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	ikesaKey.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	ikesaKey.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	ikesaKey.SK_pr = keyStream[:length_SK_pr]

	// Set security objects
	ikesaKey.Prf_d = ikesaKey.PrfInfo.Init(ikesaKey.SK_d)
	ikesaKey.Integ_i = ikesaKey.IntegInfo.Init(ikesaKey.SK_ai)
	ikesaKey.Integ_r = ikesaKey.IntegInfo.Init(ikesaKey.SK_ar)

	var err error
	ikesaKey.Encr_i, err = ikesaKey.EncrInfo.NewCrypto(ikesaKey.SK_ei)
	if err != nil {
		return err
	}

	ikesaKey.Encr_r, err = ikesaKey.EncrInfo.NewCrypto(ikesaKey.SK_er)
	if err != nil {
		return err
	}

	ikesaKey.Prf_i = ikesaKey.PrfInfo.Init(ikesaKey.SK_pi)
	ikesaKey.Prf_r = ikesaKey.PrfInfo.Init(ikesaKey.SK_pr)

	return nil
}

// ChildSAKey holds Child SA keying material and algorithms
// SPI
// Child SA transform types
type ChildSAKey struct {
	DhInfo     dh.DHType
	EncrKInfo  encr.ENCRType
	IntegKInfo integ.INTEGKType
	EsnInfo    esn.ESN

	// Security
	InitiatorToResponderEncryptionKey []byte
	ResponderToInitiatorEncryptionKey []byte
	InitiatorToResponderIntegrityKey  []byte
	ResponderToInitiatorIntegrityKey  []byte
}

func (childsaKey *ChildSAKey) ToProposal() (*message.Proposal, error) {
	p := new(message.Proposal)
	p.ProtocolID = message.TypeESP
	if childsaKey.DhInfo != nil {
		p.DiffieHellmanGroup = append(p.DiffieHellmanGroup, dh.ToTransform(childsaKey.DhInfo))
	}
	encrKTransform, err := encr.ToTransform(childsaKey.EncrKInfo)
	if err != nil {
		return nil, fmt.Errorf("ChildSAKey ToProposal: %w", err)
	}
	p.EncryptionAlgorithm = append(p.EncryptionAlgorithm, encrKTransform)
	if childsaKey.IntegKInfo != nil {
		p.IntegrityAlgorithm = append(p.IntegrityAlgorithm, integ.ToTransformChildSA(childsaKey.IntegKInfo))
	}
	p.ExtendedSequenceNumbers = append(p.ExtendedSequenceNumbers, esn.ToTransform(childsaKey.EsnInfo))
	return p, nil
}

// NewChildSAKeyByProposal creates a new ChildSAKey from a proposal
func NewChildSAKeyByProposal(proposal *message.Proposal) (*ChildSAKey, error) {
	if proposal == nil {
		return nil, fmt.Errorf("proposal is nil")
	}
	if len(proposal.EncryptionAlgorithm) == 0 || len(proposal.IntegrityAlgorithm) == 0 || len(proposal.ExtendedSequenceNumbers) == 0 {
		return nil, fmt.Errorf("proposal missing required transforms")
	}

	childsaKey := &ChildSAKey{}
	if len(proposal.DiffieHellmanGroup) == 1 {
		childsaKey.DhInfo = dh.DecodeTransform(proposal.DiffieHellmanGroup[0])
		if childsaKey.DhInfo == nil {
			return nil, fmt.Errorf("unsupported DiffieHellmanGroup[%v]", proposal.DiffieHellmanGroup[0].TransformID)
		}
	}
	childsaKey.EncrKInfo = encr.DecodeTransform(proposal.EncryptionAlgorithm[0])
	if childsaKey.EncrKInfo == nil {
		return nil, fmt.Errorf("unsupported encryption algorithm[%v]", proposal.EncryptionAlgorithm[0].TransformID)
	}
	if len(proposal.IntegrityAlgorithm) == 1 {
		childsaKey.IntegKInfo = integ.DecodeTransformChildSA(proposal.IntegrityAlgorithm[0])
		if childsaKey.IntegKInfo == nil {
			return nil, fmt.Errorf("unsupported integrity algorithm[%v]", proposal.IntegrityAlgorithm[0].TransformID)
		}
	}
	var err error
	childsaKey.EsnInfo, err = esn.DecodeTransform(proposal.ExtendedSequenceNumbers[0])
	if err != nil {
		return nil, fmt.Errorf("NewChildSAKeyByProposal: %w", err)
	}
	return childsaKey, nil
}

// GenerateKeyForChildSA derives all Child SA keys as specified in RFC 7296
func (childsaKey *ChildSAKey) GenerateKeyForChildSA(
	ikeSA *IKESAKey,
	concatenatedNonce []byte,
) error {
	// Check parameters
	if ikeSA == nil {
		logger.IKELog.Errorf("IKE SA is nil")
		return fmt.Errorf("IKE SA is nil")
	}
	if childsaKey == nil {
		logger.IKELog.Errorf("child SA is nil")
		return fmt.Errorf("child SA is nil")
	}

	// Check if the context contain needed data
	if ikeSA.PrfInfo == nil {
		logger.IKELog.Errorf("no pseudorandom function specified")
		return fmt.Errorf("no pseudorandom function specified")
	}
	if childsaKey.EncrKInfo == nil {
		logger.IKELog.Errorf("no encryption algorithm specified")
		return fmt.Errorf("no encryption algorithm specified")
	}
	if ikeSA.Prf_d == nil {
		logger.IKELog.Errorf("no key deriving key")
		return fmt.Errorf("no key deriving key")
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int

	lengthEncryptionKeyIPSec = childsaKey.EncrKInfo.GetKeyLength()
	if childsaKey.IntegKInfo != nil {
		lengthIntegrityKeyIPSec = childsaKey.IntegKInfo.GetKeyLength()
	}
	totalKeyLength = (lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec) * 2

	// Generate key for child security association as specified in RFC 7296 section 2.17
	seed := concatenatedNonce

	keyStream := prfPlus(ikeSA.Prf_d, seed, totalKeyLength)
	if keyStream == nil {
		logger.IKELog.Errorf("error happened in PrfPlus")
		return fmt.Errorf("error happened in PrfPlus")
	}

	childsaKey.InitiatorToResponderEncryptionKey = append(
		childsaKey.InitiatorToResponderEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childsaKey.InitiatorToResponderIntegrityKey = append(
		childsaKey.InitiatorToResponderIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childsaKey.ResponderToInitiatorEncryptionKey = append(
		childsaKey.ResponderToInitiatorEncryptionKey,
		keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childsaKey.ResponderToInitiatorIntegrityKey = append(
		childsaKey.ResponderToInitiatorIntegrityKey,
		keyStream[:lengthIntegrityKeyIPSec]...)

	return nil
}

func prfPlus(prf hash.Hash, s []byte, streamLen int) []byte {
	var stream, block []byte
	for i := 1; len(stream) < streamLen; i++ {
		prf.Reset()
		if _, err := prf.Write(append(append(block, s...), byte(i))); err != nil {
			return nil
		}
		stream = prf.Sum(stream)
		block = stream[len(stream)-prf.Size():]
	}
	return stream[:streamLen]
}

// Certificate
func CompareRootCertificate(
	ca []byte,
	certificateEncoding uint8,
	requestedCertificateAuthorityHash []byte,
) bool {
	if certificateEncoding != message.X509CertificateSignature {
		logger.IKELog.Errorf("not supported certificate type: %d. Reject", certificateEncoding)
		return false
	}

	if len(ca) == 0 {
		logger.IKELog.Errorln("certificate authority in context is empty")
		return false
	}

	return bytes.Equal(ca, requestedCertificateAuthorityHash)
}
