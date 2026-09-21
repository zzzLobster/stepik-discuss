package main

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/admin"
	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/config"
	"github.com/zzzLobster/stepik-discuss/gate/handlers"
	"github.com/zzzLobster/stepik-discuss/gate/ratelimit"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

//go:embed templates/*.html
var tplFS embed.FS

//go:embed static/*
var contentFS embed.FS

func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var rev, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if modified == "true" {
		rev += "-dirty"
	}
	return rev
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config invalid", "err", err)
		os.Exit(1)
	}
	store, err := sessions.Open(cfg.DBPath, cfg.TokenKey)
	if err != nil {
		log.Error("session store open failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()
	stop := make(chan struct{})
	defer close(stop)
	store.StartSweeper(stop)

	step := stepik.New(cfg.TeacherID, log)
	limits := ratelimit.NewStore()
	checker := &auth.Checker{Cfg: cfg, Store: store, Stepik: step, Limits: limits, Log: log}
	adm := &admin.Admin{Store: store, Origin: cfg.Origin, Log: log}
	checker.StartTeacherRefresh(stop)

	tpl, err := template.ParseFS(tplFS, "templates/*.html")
	if err != nil {
		log.Error("template parse failed", "err", err)
		os.Exit(1)
	}
	staticFS, err := fs.Sub(contentFS, "static")
	if err != nil {
		log.Error("static fs failed", "err", err)
		os.Exit(1)
	}
	srv := handlers.New(cfg, store, step, limits, checker, adm, log, tpl, staticFS)

	httpSrv := newHTTPServer(":8081", srv.Routes())
	log.Info("gate listening", "addr", ":8081", "placeholder", cfg.Placeholder, "revision", buildRevision())
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Error("gate stopped", "err", err)
		os.Exit(1)
	}
}

// newHTTPServer returns the production HTTP server config. MaxHeaderBytes is
// capped at 64 KB: the Go default of 1 MiB is larger than necessary for the
// gate and increases memory pressure under header-based DoS.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 * 1024, // 64 KB
	}
}
