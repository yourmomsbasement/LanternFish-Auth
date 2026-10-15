package gate

import (
	"embed"
	"mime"
	"net/http"
	"path"
)

//go:embed web/*
var webFiles embed.FS

const pageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func (g *Gate) serveStatic(name string) http.HandlerFunc {
	body, err := webFiles.ReadFile("web/" + name)
	if err != nil {
		panic(err)
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", ctype)
		h.Set("Content-Security-Policy", pageCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache")
		w.Write(body)
	}
}
