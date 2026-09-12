package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSHub manages WebSocket client connections and broadcasts callback events.
type WSHub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
}

// NewWSHub creates a new WebSocket hub.
func NewWSHub() *WSHub {
	return &WSHub{
		clients: make(map[*websocket.Conn]struct{}),
	}
}

var upgrader = websocket.Upgrader{}

// ServeWS upgrades an HTTP connection to WebSocket and registers the client.
func (h *WSHub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade error: %v", err)
		return
	}
	h.mu.Lock()
	conn.SetReadLimit(1024)
	h.clients[conn] = struct{}{}
	h.mu.Unlock()

	log.Printf("[ws] client connected from %s", r.RemoteAddr)

	// Read loop: keep connection alive and clean up on close.
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.clients, conn)
			h.mu.Unlock()
			conn.Close()
			log.Printf("[ws] client disconnected from %s", r.RemoteAddr)
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

// Broadcast sends a JSON-encoded event to all connected WebSocket clients.
func (h *WSHub) Broadcast(event interface{}) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[ws] marshal error: %v", err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.clients {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			delete(h.clients, conn)
			conn.Close()
			log.Printf("[ws] write error: %v", err)
		}
	}
}
