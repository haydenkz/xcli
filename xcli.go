package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// Config represents the JSON configuration structure.
type Config struct {
	ClientID string `json:"client_id"`
}

// loadConfig loads the configuration from /etc/xcli/config.
func loadConfig() (*Config, error) {
	const configPath = "/etc/xcli/config"
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// authResult holds the authorization code or an error from the redirect.
type authResult struct {
	code string
	err  error
}

// generateCodeVerifier creates a random string for the PKCE code verifier.
func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge computes the code challenge from the verifier.
func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// openBrowser opens the given URL in the default browser (Linux only).
func openBrowser(url string) error {
	// Linux-only implementation using xdg-open.
	cmd := exec.Command("xdg-open", url)
	return cmd.Start()
}

// postTweet uses the provided access token to post a tweet with the given text.
func postTweet(accessToken, text string) error {
	// Create JSON payload.
	payload := map[string]string{"text": text}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal tweet payload: %w", err)
	}

	// Prepare the POST request.
	req, err := http.NewRequest("POST", "https://api.twitter.com/2/tweets", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create tweet request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error posting tweet: %w", err)
	}
	defer resp.Body.Close()

	// Read response for logging.
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("tweet post failed (status %d): %s", resp.StatusCode, string(body))
	}

	fmt.Println("Tweet posted successfully!")
	return nil
}

func main() {
	// Load the configuration from /etc/xcli/config.
	cfg, err := loadConfig()
	if err != nil || cfg.ClientID == "" {
		fmt.Fprintln(os.Stderr, "Client ID not found. Please run the install script to set up /etc/xcli/config with your CLIENT ID.")
		os.Exit(1)
	}
	clientID := cfg.ClientID

	// Define the scopes required for posting and reading tweets.
	scopes := "tweet.write tweet.read users.read"
	// Redirect URI must match what’s registered in the X Developer Portal.
	redirectURI := "http://localhost:5000/callback"

	// Step 1: Generate PKCE code verifier and challenge.
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating code verifier: %v\n", err)
		os.Exit(1)
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Step 2: Construct the authorization URL.
	authURL := fmt.Sprintf(
		"https://twitter.com/i/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=random_state&code_challenge=%s&code_challenge_method=S256",
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scopes),
		url.QueryEscape(codeChallenge),
	)

	// Step 3: Set up a channel and HTTP server to capture the redirect.
	codeChan := make(chan authResult, 1)
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Extract the authorization code from the query parameters.
		code := r.URL.Query().Get("code")
		if code != "" {
			fmt.Fprintf(w, "Authorization successful. You can close this window.")
			codeChan <- authResult{code: code}
		} else {
			errDesc := r.URL.Query().Get("error_description")
			if errDesc == "" {
				errDesc = "Unknown error"
			}
			fmt.Fprintf(w, "Authorization failed: %s", errDesc)
			codeChan <- authResult{err: fmt.Errorf("authorization failed: %s", errDesc)}
		}
	})
	server := &http.Server{Addr: ":5000"}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			os.Exit(1)
		}
	}()

	// Step 4: Open the authorization URL in the default browser.
	fmt.Println("Opening authorization page in your default browser...")
	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error opening browser: %v\n", err)
		os.Exit(1)
	}

	// Step 5: Wait for the authorization code or an error.
	result := <-codeChan
	if result.err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", result.err)
		os.Exit(1)
	}
	code := result.code

	// Step 6: Shut down the HTTP server gracefully.
	if err := server.Shutdown(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error shutting down server: %v\n", err)
	}

	// Step 7: Exchange the authorization code for an access token.
	tokenURL := "https://api.twitter.com/2/oauth2/token"
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error requesting token: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Token request failed with status: %d\n", resp.StatusCode)
		os.Exit(1)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding token response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Access Token acquired successfully!")
	fmt.Println("Token Type:", tokenResp.TokenType)
	fmt.Println("Expires In (seconds):", tokenResp.ExpiresIn)

	// Begin command loop for posting tweets.
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\nEnter tweet text to post (type 'exit' to quit):")
	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			continue
		}
		input = strings.TrimSpace(input)
		if strings.EqualFold(input, "exit") || strings.EqualFold(input, "quit") {
			fmt.Println("Exiting. Goodbye!")
			break
		}
		if input == "" {
			continue
		}
		if err := postTweet(tokenResp.AccessToken, input); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to post tweet: %v\n", err)
		}
	}
}
