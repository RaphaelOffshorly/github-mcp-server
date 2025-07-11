package ghmcp

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/github/github-mcp-server/pkg/encryption"
	"github.com/gorilla/mux"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
)

type SSEServerConfig struct {
	// Version of the server
	Version string

	// GitHub Host to target for API requests (e.g. github.com or github.enterprise.com)
	Host string

	// EnabledToolsets is a list of toolsets to enable
	EnabledToolsets []string

	// Whether to enable dynamic toolsets
	DynamicToolsets bool

	// ReadOnly indicates if we should only register read-only tools
	ReadOnly bool

	// Port to run the SSE server on
	Port int

	// Host to bind the HTTP server to (e.g. 0.0.0.0, 127.0.0.1)
	BindHost string

	// Encryption key for decrypting tokens
	EncryptionKey string

	// EnableCommandLogging indicates if we should log commands
	EnableCommandLogging bool

	// Path to the log file if not stderr
	LogFilePath string
}

type SSEConnection struct {
	UserID   string
	Token    string
	Writer   http.ResponseWriter
	Request  *http.Request
	Server   *server.MCPServer
	Cancel   context.CancelFunc
	LastPing time.Time
}

type SSEServer struct {
	config      SSEServerConfig
	connections map[string]*SSEConnection
	logger      *logrus.Logger
}

func NewSSEServer(cfg SSEServerConfig) (*SSEServer, error) {
	logger := logrus.New()
	if cfg.LogFilePath != "" {
		file, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		logger.SetOutput(file)
	}
	logger.SetLevel(logrus.DebugLevel)

	return &SSEServer{
		config:      cfg,
		connections: make(map[string]*SSEConnection),
		logger:      logger,
	}, nil
}

func (s *SSEServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Cache-Control")

	// Get query parameters
	token := r.URL.Query().Get("token")
	encrypted := r.URL.Query().Get("encrypted")
	userID := r.URL.Query().Get("user_id")

	if token == "" {
		s.writeSSEError(w, "missing token parameter")
		return
	}

	if userID == "" {
		// Generate a simple user ID based on request info
		userID = fmt.Sprintf("user_%d", time.Now().Unix())
	}

	// Decrypt token if needed
	finalToken := token
	if encrypted == "true" {
		if s.config.EncryptionKey == "" {
			s.writeSSEError(w, "encryption key not configured")
			return
		}

		preparedKey, err := encryption.PrepareKey(s.config.EncryptionKey)
		if err != nil {
			s.logger.Errorf("failed to prepare encryption key: %v", err)
			s.writeSSEError(w, "encryption key error")
			return
		}

		decryptedToken, err := encryption.Decrypt(token, preparedKey)
		if err != nil {
			s.logger.Errorf("failed to decrypt token: %v", err)
			s.writeSSEError(w, "token decryption failed")
			return
		}
		finalToken = decryptedToken
	}

	// Create MCP server instance for this user
	mcpServer, err := NewMCPServer(MCPServerConfig{
		Version:         s.config.Version,
		Host:            s.config.Host,
		Token:           finalToken,
		EnabledToolsets: s.config.EnabledToolsets,
		DynamicToolsets: s.config.DynamicToolsets,
		ReadOnly:        s.config.ReadOnly,
		Translator:      nil, // Will use default translations
	})
	if err != nil {
		s.logger.Errorf("failed to create MCP server for user %s: %v", userID, err)
		s.writeSSEError(w, "failed to initialize GitHub connection")
		return
	}

	// Create context for this connection
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Create SSE connection
	conn := &SSEConnection{
		UserID:   userID,
		Token:    finalToken,
		Writer:   w,
		Request:  r,
		Server:   mcpServer,
		Cancel:   cancel,
		LastPing: time.Now(),
	}

	// Store connection
	s.connections[userID] = conn
	defer func() {
		delete(s.connections, userID)
		s.logger.Infof("SSE connection closed for user %s", userID)
	}()

	s.logger.Infof("New SSE connection established for user %s", userID)

	// Send initial connection success event
	s.writeSSEEvent(w, "connected", map[string]interface{}{
		"user_id": userID,
		"message": "Connected to GitHub MCP Server",
		"version": s.config.Version,
	})

	// Start ping ticker
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Handle connection
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send ping
			if err := s.writeSSEEvent(w, "ping", map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}); err != nil {
				s.logger.Errorf("failed to send ping to user %s: %v", userID, err)
				return
			}
			conn.LastPing = time.Now()
		}
	}
}

func (s *SSEServer) writeSSEError(w http.ResponseWriter, message string) {
	s.writeSSEEvent(w, "error", map[string]interface{}{
		"message": message,
	})
}

func (s *SSEServer) writeSSEEvent(w http.ResponseWriter, eventType string, data interface{}) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming unsupported")
	}

	// Write event type
	if eventType != "" {
		fmt.Fprintf(w, "event: %s\n", eventType)
	}

	// Write data
	fmt.Fprintf(w, "data: %v\n\n", data)

	// Flush the data
	flusher.Flush()
	return nil
}

func (s *SSEServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "healthy", "connections": %d, "version": "%s"}`, 
		len(s.connections), s.config.Version)
}

func (s *SSEServer) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	stats := map[string]interface{}{
		"total_connections": len(s.connections),
		"version":          s.config.Version,
		"connections":      []map[string]interface{}{},
	}
	
	for userID, conn := range s.connections {
		stats["connections"] = append(stats["connections"].([]map[string]interface{}), map[string]interface{}{
			"user_id":   userID,
			"last_ping": conn.LastPing.Unix(),
			"connected": time.Since(conn.LastPing).Seconds(),
		})
	}
	
	fmt.Fprintf(w, `%v`, stats)
}

func (s *SSEServer) Start() error {
	router := mux.NewRouter()
	
	// SSE endpoint
	router.HandleFunc("/sse", s.handleSSE).Methods("GET")
	
	// Health check endpoint
	router.HandleFunc("/health", s.handleHealth).Methods("GET")
	
	// Stats endpoint
	router.HandleFunc("/stats", s.handleStats).Methods("GET")

	// Create HTTP server
	bindHost := s.config.BindHost
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", bindHost, s.config.Port),
		Handler: router,
	}

	// Create app context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start server in goroutine
	go func() {
		s.logger.Infof("Starting SSE server on port %d", s.config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Errorf("SSE server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	s.logger.Info("Shutting down SSE server...")

	// Close all connections
	for userID, conn := range s.connections {
		conn.Cancel()
		s.logger.Infof("Closed connection for user %s", userID)
	}

	// Shutdown server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		s.logger.Errorf("Server shutdown error: %v", err)
		return err
	}

	s.logger.Info("SSE server stopped")
	return nil
}

func RunSSEServer(cfg SSEServerConfig) error {
	server, err := NewSSEServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create SSE server: %w", err)
	}

	return server.Start()
}
