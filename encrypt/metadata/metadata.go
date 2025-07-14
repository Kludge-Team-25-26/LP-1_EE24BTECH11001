package metadata

type FileInfo struct {
	OriginalName        string `json:"original_name"`
	OriginalSize        int64  `json:"original_size"`
	ChunkSize           int    `json:"chunk_size"`
	TotalChunks         int    `json:"total_chunks"`
	EncryptionAlgorithm string `json:"encryption_algorithm"`
	KeyEncryption       string `json:"key_encryption"`
}

type ChunkMetadata struct {
	ChunkID       int    `json:"chunk_id"`
	EncryptedFile string `json:"encrypted_file"`
	IV            string `json:"iv"`       // base64-encoded IV
	Checksum      string `json:"checksum"` // SHA-256 checksum of original chunk (hex)
	Size          int    `json:"size"`     // original (unencrypted) size
}

// EncryptionKeys stores information needed to reconstruct the CEK
type EncryptionKeys struct {
	EncryptedMasterKey   string `json:"encrypted_master_key"`   // base64-encoded encrypted CEK
	IV                   string `json:"iv"`                     // IV used to encrypt CEK (base64)
	EphemeralPublicKey   string `json:"ephemeral_public_key"`   // base64-encoded ECC ephemeral pubkey
	PublicKeyFingerprint string `json:"public_key_fingerprint"` // hex sha256 of recipient's ECC pubkey
}

type Metadata struct {
	FileInfo FileInfo        `json:"file_info"`
	Chunks   []ChunkMetadata `json:"chunks"`
	Keys     EncryptionKeys  `json:"keys"`
}
