/*
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"task_1/encrypt"
)

func main() {
	// Define CLI flags
	inputPath := flag.String("in", "", "Path to the input file to encrypt (required)")
	outputDir := flag.String("out", "output", "Directory to store encrypted chunks and metadata")
	publicKeyPath := flag.String("pub", "", "Path to recipient's ECC (P-384) public key in base64 (required)")
	chunkSize := flag.Int("chunk", 1024*1024, "Chunk size in bytes (default 1MB)")

	flag.Parse()

	// Validate required flags
	if *inputPath == "" || *publicKeyPath == "" {
		fmt.Println("Error: -in and -pub are required.")
		flag.Usage()
		os.Exit(1)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0700); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🔐 Encrypting file...")
	meta, err := encrypt.EncryptFile(*inputPath, *outputDir, *publicKeyPath, *chunkSize)
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Encryption complete!")
	fmt.Println("✅ Encryption complete!")
	fmt.Printf("Original file: %s (%d bytes), split into %d chunk(s)\n",
		meta.FileInfo.OriginalName,
		meta.FileInfo.OriginalSize,
		meta.FileInfo.TotalChunks,
	)
}
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"task_1/decrypt"
	"task_1/encrypt"
)

func main() {
	// Mode flags
	encryptMode := flag.Bool("e", false, "Run encryption")
	decryptMode := flag.Bool("d", false, "Run decryption")

	// Common flags
	inputPath := flag.String("i", "", "Path to the input file for encryption")
	outputDir := flag.String("o", "output", "Directory to store encrypted chunks and metadata")
	publicKeyPath := flag.String("pub", "", "Path to recipient's public key (base64)")

	metaPath := flag.String("m", "", "Path to metadata.json for decryption")
	privateKeyPath := flag.String("priv", "", "Path to recipient's private key")
	chunksDir := flag.String("c", "", "Path to directory with encrypted chunks")

	chunkSize := flag.Int("chunk", 1024*1024, "Chunk size in bytes for encryption (default 1MB)")
	flag.Parse()

	switch {
	case *encryptMode:
		if *inputPath == "" || *publicKeyPath == "" {
			log.Fatal("Encryption mode: -in and -pub are required.")
		}
		err := os.MkdirAll(*outputDir, 0700)
		if err != nil {
			log.Fatalf("Failed to create output directory: %v", err)
		}
		meta, err := encrypt.EncryptFile(*inputPath, *outputDir, *publicKeyPath, *chunkSize)
		if err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
		fmt.Printf("Encryption complete. Metadata at: %s\n", filepath.Join(*outputDir, "metadata.json"))
		fmt.Printf("Original file: %s (%d bytes) → %d chunks\n",
			meta.FileInfo.OriginalName, meta.FileInfo.OriginalSize, meta.FileInfo.TotalChunks)

	case *decryptMode:
		if *metaPath == "" || *privateKeyPath == "" || *chunksDir == "" {
			log.Fatal("Decryption mode: -m, -p, and -c are required.")
		}
		err := decrypt.DecryptFile(*metaPath, *privateKeyPath, *chunksDir)
		if err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
		fmt.Println("Decryption complete.")

	default:
		fmt.Println("Please specify either -e (encrypt) or -d (decrypt) mode.")
		flag.Usage()
		os.Exit(1)
	}
}
