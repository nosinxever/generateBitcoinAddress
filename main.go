package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/bech32"
	"golang.org/x/crypto/ripemd160"
)

const suffix = "youstr"

var count int64 // Atomic counter

func main() {
	start := time.Now()                  // Start time measurement
	runtime.GOMAXPROCS(runtime.NumCPU()) // Use all available CPUs
	var wg sync.WaitGroup

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				address, segwitAddress, p2shSegwitAddress, wif := generateAddresses()
				fmt.Printf("Function called %d times\n", atomic.LoadInt64(&count))

				if strings.HasSuffix(address, suffix) || strings.HasSuffix(segwitAddress, suffix) || strings.HasSuffix(p2shSegwitAddress, suffix) {
					duration := time.Since(start) // Calculate duration
					fmt.Printf("Legacy Address: %s\n", address)
					fmt.Printf("SegWit Address: %s\n", segwitAddress)
					fmt.Printf("P2SH-SegWit Address: %s\n", p2shSegwitAddress)
					fmt.Printf("Private Key WIF: %s\n", wif)
					fmt.Printf("Time taken: %s\n", duration)
					return
				}
			}
		}()
	}
	wg.Wait() // Wait for the first successful generation
}

func generateAddresses() (string, string, string, string) {
	atomic.AddInt64(&count, 1) // Increment the call count atomically
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	pubKey := publicKeyBytes(&privateKey.PublicKey)
	pubKeyHash := hashPubKey(pubKey)
	legacyAddress := generateLegacyAddress(pubKeyHash)
	segwitAddress := generateSegwitAddress(pubKey)
	p2shSegwitAddress := generateP2SHSegwitAddress(pubKey)

	wif := encodeToWIF(privateKey)

	return legacyAddress, segwitAddress, p2shSegwitAddress, wif
}

func publicKeyBytes(publicKey *ecdsa.PublicKey) []byte {
	return elliptic.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y)
}

func hashPubKey(pubKey []byte) []byte {
	shaHash := sha256.New()
	shaHash.Write(pubKey)
	ripeHasher := ripemd160.New()
	ripeHasher.Write(shaHash.Sum(nil))
	return ripeHasher.Sum(nil)
}

func generateLegacyAddress(pubKeyHash []byte) string {
	versionedPayload := append([]byte{0x00}, pubKeyHash...)
	checksum := checksum(versionedPayload)
	fullPayload := append(versionedPayload, checksum...)
	return base58.Encode(fullPayload)
}

func generateSegwitAddress(pubKey []byte) string {
	sha256Hash := sha256.Sum256(pubKey)
	ripeHasher := ripemd160.New()
	ripeHasher.Write(sha256Hash[:])
	pubKeyHash := ripeHasher.Sum(nil)
	data, err := bech32.ConvertBits(pubKeyHash, 8, 5, true)
	if err != nil {
		log.Fatal(err)
	}
	bech32Addr, err := bech32.Encode("bc", append([]byte{0x00}, data...))
	if err != nil {
		log.Fatal(err)
	}
	return bech32Addr
}

func generateP2SHSegwitAddress(pubKey []byte) string {
	sha256Hash := sha256.Sum256(pubKey)
	ripeHasher := ripemd160.New()
	ripeHasher.Write(sha256Hash[:])
	pubKeyHash := ripeHasher.Sum(nil)
	redeemScript := append([]byte{0x00, 0x14}, pubKeyHash...)
	scriptPubKeyHash := hashPubKey(redeemScript)
	fullPayload := append([]byte{0x05}, scriptPubKeyHash...)
	checksum := checksum(fullPayload)
	finalPayload := append(fullPayload, checksum...)
	return base58.Encode(finalPayload)
}

func checksum(payload []byte) []byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return second[:4]
}

func encodeToWIF(privateKey *ecdsa.PrivateKey) string {
	d := privateKey.D.Bytes()
	fullKey := append([]byte{0x80}, d...) // Version byte for mainnet private keys
	fullKey = append(fullKey, 0x01)       // Compression flag

	checksum := checksum(fullKey)
	fullKey = append(fullKey, checksum...)
	return base58.Encode(fullKey)
}
