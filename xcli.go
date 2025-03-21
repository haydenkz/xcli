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

// Tweet represents a tweet from the API response.
type Tweet struct {
    ID            string `json:"id"`
    Text          string `json:"text"`
    AuthorID      string `json:"author_id"`
    PublicMetrics struct {
        LikeCount  int `json:"like_count"`
        ReplyCount int `json:"reply_count"`
    } `json:"public_metrics"`
}

// SearchResponse represents the full API response for tweet searches.
type SearchResponse struct {
    Data     []Tweet `json:"data"`
    Includes struct {
        Users []User `json:"users"`
    } `json:"includes"`
    Errors []struct {
        Detail string `json:"detail"`
        Title  string `json:"title"`
    } `json:"errors,omitempty"`
}

// User represents a user from the API response.
type User struct {
    ID            string `json:"id"`
    Name          string `json:"name"`
    Username      string `json:"username"`
    Protected     bool   `json:"protected"`
    PublicMetrics struct {
        FollowersCount int `json:"followers_count"`
        FollowingCount int `json:"following_count"`
    } `json:"public_metrics"`
}

// UserLookupResponse represents the response for user lookup.
type UserLookupResponse struct {
    Data   User `json:"data"`
    Errors []struct {
        Detail string `json:"detail"`
        Title  string `json:"title"`
    } `json:"errors,omitempty"`
}

// TweetsResponse represents the response for user tweets.
type TweetsResponse struct {
    Data   []Tweet `json:"data"`
    Errors []struct {
        Detail string `json:"detail"`
        Title  string `json:"title"`
    } `json:"errors,omitempty"`
}

// authResult holds the authorization code or an error from the redirect.
type authResult struct {
    code string
    err  error
}

// loadConfig loads the configuration from a specified path.
func loadConfig(path string) (*Config, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("failed to open config file: %w", err)
    }
    defer file.Close()

    var cfg Config
    if err := json.NewDecoder(file).Decode(&cfg); err != nil {
        return nil, fmt.Errorf("failed to decode config: %w", err)
    }
    if cfg.ClientID == "" {
        return nil, fmt.Errorf("client_id is missing in config")
    }
    return &cfg, nil
}

// generateCodeVerifier creates a random string for the PKCE code verifier.
func generateCodeVerifier() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("failed to generate code verifier: %w", err)
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
    cmd := exec.Command("xdg-open", url)
    return cmd.Start()
}

// searchTweets searches for recent tweets matching the query.
func searchTweets(accessToken, query string) error {
    apiURL := "https://api.twitter.com/2/tweets/search/recent"
    params := url.Values{
        "query":        {query},
        "max_results":  {"10"},
        "tweet.fields": {"public_metrics"},
        "expansions":   {"author_id"},
        "user.fields":  {"username"},
    }
    req, err := http.NewRequest("GET", apiURL+"?"+params.Encode(), nil)
    if err != nil {
        return fmt.Errorf("failed to create search request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("error performing search: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("search failed with status %d: %s", resp.StatusCode, body)
    }

    var searchResp SearchResponse
    if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
        return fmt.Errorf("error decoding search response: %w", err)
    }

    if len(searchResp.Errors) > 0 {
        for _, e := range searchResp.Errors {
            fmt.Printf("Error: %s - %s\n", e.Title, e.Detail)
        }
        return nil
    }

    if len(searchResp.Data) == 0 {
        fmt.Println("No tweets found for the query.")
        return nil
    }

    userMap := make(map[string]string)
    for _, user := range searchResp.Includes.Users {
        userMap[user.ID] = user.Username
    }

    for i, tweet := range searchResp.Data {
        username := userMap[tweet.AuthorID]
        if username == "" {
            username = "Unknown"
        }
        fmt.Printf("Tweet %d:\n", i+1)
        fmt.Printf("Username: @%s\n", username)
        fmt.Printf("Text: %s\n", tweet.Text)
        fmt.Printf("Likes: %d\n", tweet.PublicMetrics.LikeCount)
        fmt.Printf("Comments: %d\n", tweet.PublicMetrics.ReplyCount)
        fmt.Println("---")
    }
    return nil
}

// lookupUser retrieves user information and their recent tweets.
func lookupUser(accessToken, username string) error {
    userURL := fmt.Sprintf("https://api.twitter.com/2/users/by/username/%s", url.PathEscape(username))
    params := url.Values{"user.fields": {"public_metrics"}}
    req, err := http.NewRequest("GET", userURL+"?"+params.Encode(), nil)
    if err != nil {
        return fmt.Errorf("failed to create user lookup request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("error performing user lookup: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("user lookup failed with status %d: %s", resp.StatusCode, body)
    }

    var userResp UserLookupResponse
    if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
        return fmt.Errorf("error decoding user lookup response: %w", err)
    }

    if len(userResp.Errors) > 0 {
        for _, e := range userResp.Errors {
            fmt.Printf("Error: %s - %s\n", e.Title, e.Detail)
        }
        return nil
    }

    user := userResp.Data
    tweetsURL := fmt.Sprintf("https://api.twitter.com/2/users/%s/tweets", user.ID)
    params = url.Values{"max_results": {"10"}}
    req, err = http.NewRequest("GET", tweetsURL+"?"+params.Encode(), nil)
    if err != nil {
        return fmt.Errorf("failed to create tweets request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)

    resp, err = http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("error fetching tweets: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("tweets fetch failed with status %d: %s", resp.StatusCode, body)
    }

    var tweetsResp TweetsResponse
    if err := json.NewDecoder(resp.Body).Decode(&tweetsResp); err != nil {
        return fmt.Errorf("error decoding tweets response: %w", err)
    }

    if len(tweetsResp.Errors) > 0 {
        for _, e := range tweetsResp.Errors {
            fmt.Printf("Error: %s - %s\n", e.Title, e.Detail)
        }
        return nil
    }

    fmt.Printf("Name: %s\n", user.Name)
    fmt.Printf("Username: @%s\n", user.Username)
    fmt.Printf("Followers: %d\n", user.PublicMetrics.FollowersCount)
    fmt.Printf("Following: %d\n", user.PublicMetrics.FollowingCount)

    fmt.Println("\nRecent Tweets:")
    if len(tweetsResp.Data) == 0 {
        fmt.Println("No recent tweets found.")
    } else {
        for i, tweet := range tweetsResp.Data {
            fmt.Printf("%d. %s\n", i+1, tweet.Text)
        }
    }
    return nil
}

// postTweet posts a tweet with the given text.
func postTweet(accessToken, text string) error {
    payload := map[string]string{"text": text}
    payloadBytes, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("failed to marshal tweet payload: %w", err)
    }

    req, err := http.NewRequest("POST", "https://api.twitter.com/2/tweets", bytes.NewBuffer(payloadBytes))
    if err != nil {
        return fmt.Errorf("failed to create tweet request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("error posting tweet: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("tweet post failed with status %d: %s", resp.StatusCode, body)
    }

    fmt.Println("Tweet posted successfully!")
    return nil
}

func main() {
    // Configuration constants
    const (
        configPath  = "/etc/xcli/config"
        redirectURI = "http://localhost:5000/callback"
        scopes      = "tweet.write tweet.read users.read"
    )

    // Load configuration
    cfg, err := loadConfig(configPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
        os.Exit(1)
    }
    clientID := cfg.ClientID

    // Generate PKCE parameters
    codeVerifier, err := generateCodeVerifier()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating code verifier: %v\n", err)
        os.Exit(1)
    }
    codeChallenge := generateCodeChallenge(codeVerifier)
    state, err := generateCodeVerifier() // Random state for security
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating state: %v\n", err)
        os.Exit(1)
    }

    // Construct authorization URL
    authURL := fmt.Sprintf(
        "https://twitter.com/i/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
        url.QueryEscape(clientID),
        url.QueryEscape(redirectURI),
        url.QueryEscape(scopes),
        url.QueryEscape(state),
        url.QueryEscape(codeChallenge),
    )

    // Set up HTTP server for OAuth callback
    codeChan := make(chan authResult, 1)
    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Query().Get("state") != state {
            fmt.Fprintf(w, "Invalid state parameter")
            codeChan <- authResult{err: fmt.Errorf("invalid state parameter")}
            return
        }
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

    // Open browser for authorization
    fmt.Println("Opening authorization page in your default browser...")
    if err := openBrowser(authURL); err != nil {
        fmt.Fprintf(os.Stderr, "Error opening browser: %v\n", err)
        fmt.Println("Please visit this URL manually:", authURL)
    }

    // Wait for authorization result
    result := <-codeChan
    if result.err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", result.err)
        os.Exit(1)
    }
    code := result.code

    // Shutdown HTTP server
    if err := server.Shutdown(context.Background()); err != nil {
        fmt.Fprintf(os.Stderr, "Error shutting down server: %v\n", err)
    }

    // Exchange code for access token
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
        body, _ := io.ReadAll(resp.Body)
        fmt.Fprintf(os.Stderr, "Token request failed with status %d: %s\n", resp.StatusCode, body)
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

    // Command loop
    reader := bufio.NewReader(os.Stdin)
    fmt.Println("\nEnter text to post or a command ('?' for help):")
    for {
        fmt.Print("> ")
        input, err := reader.ReadString('\n')
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
            continue
        }
        input = strings.TrimSpace(input)

        switch {
        case strings.EqualFold(input, "exit") || strings.EqualFold(input, "quit"):
            fmt.Println("Goodbye!")
            return
        case input == "?" || strings.EqualFold(input, "help"):
            fmt.Println("Available commands:")
            fmt.Println("  - Type your tweet and press Enter to post it.")
            fmt.Println("  - 'search: <query>' to search for tweets containing <query>.")
            fmt.Println("  - 'lookup: <username>' to lookup user information and recent tweets.")
            fmt.Println("  - 'exit' or 'quit' to exit the program.")
            fmt.Println("  - '?' or 'help' to display this help menu.")
        case strings.HasPrefix(input, "search: "):
            query := strings.TrimSpace(strings.TrimPrefix(input, "search: "))
            if query == "" {
                fmt.Println("Please provide a search query after 'search: '")
                continue
            }
            if err := searchTweets(tokenResp.AccessToken, query); err != nil {
                fmt.Fprintf(os.Stderr, "Search failed: %v\n", err)
            }
        case strings.HasPrefix(input, "lookup: "):
            username := strings.TrimSpace(strings.TrimPrefix(input, "lookup: "))
            if username == "" {
                fmt.Println("Please provide a username after 'lookup: '")
                continue
            }
            if err := lookupUser(tokenResp.AccessToken, username); err != nil {
                fmt.Fprintf(os.Stderr, "User lookup failed: %v\n", err)
            }
        case input != "":
            if err := postTweet(tokenResp.AccessToken, input); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to post tweet: %v\n", err)
            }
        }
    }
}