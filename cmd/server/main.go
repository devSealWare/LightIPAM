package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"
)

type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Time    string `json:"time"`
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	port := getenv("PORT", "8080")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:  "ok",
			Service: "light-ipam",
			Time:    time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Light IPAM</title>
  <style>
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1d252d; }
    main { max-width: 920px; margin: 0 auto; padding: 56px 24px; }
    h1 { font-size: 42px; line-height: 1.05; margin: 0 0 12px; letter-spacing: 0; }
    p { font-size: 17px; line-height: 1.55; max-width: 680px; color: #46525f; }
    .panel { margin-top: 32px; border: 1px solid #d8dde3; border-radius: 8px; background: #fff; padding: 20px; }
    .status { display: inline-flex; align-items: center; gap: 8px; font-weight: 650; }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: #168a4a; }
    @media (prefers-color-scheme: dark) {
      body { background: #111418; color: #eef2f6; }
      p { color: #b5c0ca; }
      .panel { background: #181d23; border-color: #313944; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Light IPAM</h1>
    <p>A lightweight IP address management and network discovery system. This starter app is ready for the API, auth, database migrations, and separate scanner agents.</p>
    <section class="panel">
      <div class="status"><span class="dot"></span> Web service running</div>
    </section>
  </main>
</body>
</html>`))
	})

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Info("starting server", "port", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
