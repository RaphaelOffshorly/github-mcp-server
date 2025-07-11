package main

import (
	"fmt"
	"os"

	"github.com/github/github-mcp-server/pkg/encryption"
	"github.com/spf13/cobra"
)

var (
	encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encryption utilities",
		Long:  `Utilities for encrypting and decrypting GitHub tokens and generating encryption keys.`,
	}

	generateKeyCmd = &cobra.Command{
		Use:   "generate-key",
		Short: "Generate a new encryption key",
		Long:  `Generate a new 32-byte encryption key for AES-256 encryption.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			key, err := encryption.GenerateKey()
			if err != nil {
				return fmt.Errorf("failed to generate key: %w", err)
			}
			fmt.Printf("Generated encryption key: %s\n", key)
			fmt.Printf("Set this as your GITHUB_ENCRYPTION_KEY environment variable\n")
			return nil
		},
	}

	encryptTokenCmd = &cobra.Command{
		Use:   "encrypt-token [token]",
		Short: "Encrypt a GitHub token",
		Long:  `Encrypt a GitHub Personal Access Token using the provided encryption key.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			token := args[0]
			key := os.Getenv("GITHUB_ENCRYPTION_KEY")
			if key == "" {
				return fmt.Errorf("GITHUB_ENCRYPTION_KEY environment variable not set")
			}

			preparedKey, err := encryption.PrepareKey(key)
			if err != nil {
				return fmt.Errorf("failed to prepare encryption key: %w", err)
			}

			encryptedToken, err := encryption.Encrypt(token, preparedKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt token: %w", err)
			}

			fmt.Printf("Encrypted token: %s\n", encryptedToken)
			fmt.Printf("Use this encrypted token in your SSE URL: /sse?token=%s&encrypted=true\n", encryptedToken)
			return nil
		},
	}

	decryptTokenCmd = &cobra.Command{
		Use:   "decrypt-token [encrypted-token]",
		Short: "Decrypt a GitHub token",
		Long:  `Decrypt an encrypted GitHub Personal Access Token using the provided encryption key.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			encryptedToken := args[0]
			key := os.Getenv("GITHUB_ENCRYPTION_KEY")
			if key == "" {
				return fmt.Errorf("GITHUB_ENCRYPTION_KEY environment variable not set")
			}

			preparedKey, err := encryption.PrepareKey(key)
			if err != nil {
				return fmt.Errorf("failed to prepare encryption key: %w", err)
			}

			decryptedToken, err := encryption.Decrypt(encryptedToken, preparedKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt token: %w", err)
			}

			fmt.Printf("Decrypted token: %s\n", decryptedToken)
			return nil
		},
	}
)

func init() {
	// Add encrypt subcommands
	encryptCmd.AddCommand(generateKeyCmd)
	encryptCmd.AddCommand(encryptTokenCmd)
	encryptCmd.AddCommand(decryptTokenCmd)
	
	// Add encrypt command to root
	rootCmd.AddCommand(encryptCmd)
}
