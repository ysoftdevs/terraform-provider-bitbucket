package mock_server

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Token struct {
	Name        string   `json:"name"`
	Token       string   `json:"token"`
	ExpiryDate  int64    `json:"expiryDate"`
	Permissions []string `json:"permissions"`
}

type MockBitbucketServer struct {
	Mu     sync.Mutex
	Tokens map[string][]Token // key = "project/repo"
	Server *http.Server
	URL    string
}

func NewMockBitbucketServer() *MockBitbucketServer {
	m := &MockBitbucketServer{
		Tokens: make(map[string][]Token),
	}

	mux := http.NewServeMux()

	// ---------------------------------------------------------------------
	// ONE handler, dispatching by HTTP method (GET / PUT / DELETE)
	// ---------------------------------------------------------------------
	mux.HandleFunc("/rest/access-tokens/latest/projects/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		// Expected for LIST and CREATE:
		// ["","rest","access-tokens","latest","projects",p,"repos",r]
		//
		// Expected for DELETE:
		// ["","rest","access-tokens","latest","projects",p,"repos",r,token]

		if len(parts) < 8 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}

		project := parts[4]
		repo := parts[6]
		key := project + "/" + repo

		switch r.Method {

		//------------------------------------------------------------------
		// LIST TOKENS (GET)
		//------------------------------------------------------------------
		case http.MethodGet:
			m.Mu.Lock()
			values := m.Tokens[key]
			m.Mu.Unlock()

			resp := map[string]interface{}{
				"values": values,
			}
			_ = json.NewEncoder(w).Encode(resp)

		//------------------------------------------------------------------
		// CREATE TOKEN (PUT)
		//------------------------------------------------------------------
		case http.MethodPut:
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}

			name := payload["name"].(string)
			expDays := int(payload["expiryDays"].(float64))
			expiry := time.Now().Add(time.Duration(expDays) * 24 * time.Hour).UnixMilli()

			token := Token{
				Name:       name,
				Token:      "secret-" + name,
				ExpiryDate: expiry,
				Permissions: []string{
					"REPO_READ",
				},
			}

			m.Mu.Lock()
			m.Tokens[key] = append(m.Tokens[key], token)
			m.Mu.Unlock()

			_ = json.NewEncoder(w).Encode(token)

		//------------------------------------------------------------------
		// DELETE TOKEN (DELETE)
		//------------------------------------------------------------------
		case http.MethodDelete:
			if len(parts) < 9 {
				http.Error(w, "missing token name", http.StatusBadRequest)
				return
			}

			tokenName := parts[8]

			m.Mu.Lock()
			old := m.Tokens[key]
			newList := make([]Token, 0)
			for _, t := range old {
				if t.Name != tokenName {
					newList = append(newList, t)
				}
			}
			m.Tokens[key] = newList
			m.Mu.Unlock()

			w.WriteHeader(http.StatusOK)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	m.Server = &http.Server{
		Handler: mux,
		Addr:    "127.0.0.1:0",
	}

	return m
}

// Start starts the mock server on a random port.
func (m *MockBitbucketServer) Start() error {
	ln, err := net.Listen("tcp", m.Server.Addr)
	if err != nil {
		return err
	}

	m.URL = "http://" + ln.Addr().String()
	go m.Server.Serve(ln)

	return nil
}

// Helper to simulate a drift scenario by deleting all tokens for a repo.
func (m *MockBitbucketServer) ClearTokensFor(key string) {
	m.Mu.Lock()
	m.Tokens[key] = nil
	m.Mu.Unlock()
}
