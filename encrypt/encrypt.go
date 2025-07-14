package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"task_1/encrypt/metadata"
)

/*
	Arguments :
		1. path: filepath to recipient's static public key for diffie hellman

	Returns:
		1. Usable public key object for Go
		2. sha256 hash of the public key as the fingerprint (For metadata and authentication purposes)
		3. possible error
*/

func loadECCPublicKey(path string) (*ecdh.PublicKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, "", err
	}
	pubKey, err := ecdh.P384().NewPublicKey(decoded)
	if err != nil {
		return nil, "", err
	}
	fp := fmt.Sprintf("%x", sha256.Sum256(decoded))
	return pubKey, fp, nil
}

/*
	Arguments:
		1. inputPath: filepath for file to be encrypted
		2. ouputDir: path for directory which will store encrypted chunks and the metadata json file
		3. recipientPublicKeyPath: self explanatory
		3. chunkSize: can be a 32 bit integer

	Returns:
		1. pointer to a metadat struct

	Note: This is the only visible function to the outside world (begins with caps)
*/

func EncryptFile(inputPath, outputDir, recipientPublicKeyPath string, chunkSize int) (*metadata.Metadata, error) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	info, err := inFile.Stat() // For FileInfo metadata purposes
	if err != nil {
		return nil, err
	}

	recipientPubKey, fingerprint, err := loadECCPublicKey(recipientPublicKeyPath)
	if err != nil {
		return nil, err
	}

	cek := make([]byte, 32) // This is the AES key which will be used to encrypt the content chunks (32 bytes = 256 bit len key)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}

	chunksDir := filepath.Join(outputDir, "chunks")
	if err := os.MkdirAll(chunksDir, 0700); err != nil { // MkdirAll == mkdir -p
		return nil, err
	}

	var chunks []metadata.ChunkMetadata
	buf := make([]byte, chunkSize)
	totalChunks := 0

	// Start reading input file in chunks
	for {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}

		chunkData := buf[:n]
		iv := make([]byte, 12)
		if _, err := rand.Read(iv); err != nil { // Create random 12 byte IV (AES standard = 12 byte)
			return nil, err
		}

		aesBlock, err := aes.NewCipher(cek) // create AES block cipher object
		if err != nil {
			return nil, err
		}
		aesGCM, err := cipher.NewGCM(aesBlock) // operate the AES object in GCM mode
		if err != nil {
			return nil, err
		}

		ciphertext := aesGCM.Seal(nil, iv, chunkData, nil) // encrypt the chunk

		chunkFilename := fmt.Sprintf("chunk_%d.enc", totalChunks+1)
		chunkPath := filepath.Join(chunksDir, chunkFilename)
		if err := os.WriteFile(chunkPath, ciphertext, 0600); err != nil {
			return nil, err
		}

		hash := sha256.Sum256(chunkData)
		chunks = append(chunks, metadata.ChunkMetadata{
			ChunkID:       totalChunks + 1,
			EncryptedFile: chunkFilename,
			IV:            base64.StdEncoding.EncodeToString(iv),
			Checksum:      fmt.Sprintf("%x", hash[:]), // convert fixed size array (hash) to a slice for Sprintf
			Size:          n,
		})

		totalChunks++
	}

	// Generate ephemeral ECC key pair
	ephemeralPriv, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeralPub := ephemeralPriv.PublicKey()

	// Compute shared secret
	sharedSecret, err := ephemeralPriv.ECDH(recipientPubKey)
	if err != nil {
		return nil, err
	}

	// CEK is encrypted using AES with key being sha256sum(sharedSecret)
	kek := sha256.Sum256(sharedSecret)

	// Step 6: Encrypt the CEK using KEK
	cekIV := make([]byte, 12)
	if _, err := rand.Read(cekIV); err != nil {
		return nil, err
	}
	kekBlock, err := aes.NewCipher(kek[:])
	if err != nil {
		return nil, err
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, err
	}
	encryptedCEK := kekGCM.Seal(nil, cekIV, cek, nil)

	// Prepare metadata
	meta := &metadata.Metadata{
		FileInfo: metadata.FileInfo{
			OriginalName:        filepath.Base(inputPath),
			OriginalSize:        info.Size(),
			ChunkSize:           chunkSize,
			TotalChunks:         totalChunks,
			EncryptionAlgorithm: "AES-256-GCM",
			KeyEncryption:       "ECC-P384-ECDH + AES-256-GCM",
		},
		Chunks: chunks,
		Keys: metadata.EncryptionKeys{
			EncryptedMasterKey:   base64.StdEncoding.EncodeToString(encryptedCEK),
			IV:                   base64.StdEncoding.EncodeToString(cekIV),
			EphemeralPublicKey:   base64.StdEncoding.EncodeToString(ephemeralPub.Bytes()),
			PublicKeyFingerprint: fingerprint,
		},
	}

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "metadata.json"), metaJSON, 0600); err != nil {
		return nil, err
	}

	return meta, nil
}
