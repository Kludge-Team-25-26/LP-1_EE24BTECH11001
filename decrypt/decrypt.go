package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"task_1/encrypt/metadata"
)

func loadRecipientPrivateKey(path string) (*ecdh.PrivateKey, error) {
	privData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ecdh.P384().NewPrivateKey(privData)
}

func decryptCEK(ephemeralPubBase64, encryptedCEKBase64, ivBase64 string, recipientPriv *ecdh.PrivateKey) ([]byte, error) {
	ephemeralPubBytes, err := base64.StdEncoding.DecodeString(ephemeralPubBase64)
	if err != nil {
		return nil, err
	}
	ephemeralPub, err := ecdh.P384().NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}
	kek := sha256.Sum256(sharedSecret) // Key encryption key

	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encryptedCEK, err := base64.StdEncoding.DecodeString(encryptedCEKBase64)
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return nil, err
	}

	cek, err := gcm.Open(nil, iv, encryptedCEK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CEK: %v", err)
	}

	return cek, nil
}

func decryptChunks(meta *metadata.Metadata, cek []byte, chunksDir, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	block, err := aes.NewCipher(cek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	for _, chunk := range meta.Chunks {
		iv, err := base64.StdEncoding.DecodeString(chunk.IV)
		if err != nil {
			return err
		}

		encPath := filepath.Join(chunksDir, chunk.EncryptedFile)
		encData, err := os.ReadFile(encPath)
		if err != nil {
			return err
		}

		plainData, err := gcm.Open(nil, iv, encData, nil)
		if err != nil {
			return fmt.Errorf("decryption failed for chunk %d: %v", chunk.ChunkID, err)
		}

		// Verify checksum (for integrity)
		hash := sha256.Sum256(plainData)
		checksum := fmt.Sprintf("%x", hash[:])
		if checksum != chunk.Checksum {
			return fmt.Errorf("checksum mismatch in chunk %d", chunk.ChunkID)
		}

		_, err = outFile.Write(plainData)
		if err != nil {
			return err
		}
	}

	return nil
}

func DecryptFile(metaPath, privKeyPath, chunksDir string) error {
	metaFile, err := os.Open(metaPath)
	if err != nil {
		return err
	}
	defer metaFile.Close()

	var meta metadata.Metadata
	if err := json.NewDecoder(metaFile).Decode(&meta); err != nil {
		return err
	}

	priv, err := loadRecipientPrivateKey(privKeyPath)
	if err != nil {
		return err
	}

	cek, err := decryptCEK(
		meta.Keys.EphemeralPublicKey,
		meta.Keys.EncryptedMasterKey,
		meta.Keys.IV,
		priv,
	)
	if err != nil {
		return err
	}

	outputFile := meta.FileInfo.OriginalName
	return decryptChunks(&meta, cek, chunksDir, outputFile)
}
