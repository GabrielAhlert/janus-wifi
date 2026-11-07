// Package web embute os templates HTML e os arquivos estáticos no binário.
//
//	templates/portal/  páginas vistas pelos visitantes
//	templates/admin/   painel administrativo
//	static/            CSS e JS
//
// Em cada pasta de templates, _layout.html define "layout" e cada página
// define "content".
package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
)

// O glob explícito inclui _layout.html, que o embed de diretório ignoraria.
//
//go:embed templates/*/*.html static
var files embed.FS

type Templates struct {
	Portal *Set
	Admin  *Set
}

// Set é um conjunto de páginas que compartilham o mesmo layout.
type Set struct {
	pages map[string]*template.Template
}

func Load() (*Templates, error) {
	portal, err := loadSet("templates/portal")
	if err != nil {
		return nil, err
	}
	admin, err := loadSet("templates/admin")
	if err != nil {
		return nil, err
	}
	return &Templates{Portal: portal, Admin: admin}, nil
}

func loadSet(dir string) (*Set, error) {
	layout, err := template.ParseFS(files, dir+"/_layout.html")
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return nil, err
	}
	s := &Set{pages: map[string]*template.Template{}}
	for _, e := range entries {
		name := e.Name()
		if name == "_layout.html" || !strings.HasSuffix(name, ".html") {
			continue
		}
		base, err := layout.Clone()
		if err != nil {
			return nil, err
		}
		t, err := base.ParseFS(files, dir+"/"+name)
		if err != nil {
			return nil, err
		}
		s.pages[strings.TrimSuffix(name, ".html")] = t
	}
	return s, nil
}

// Render executa a página num buffer antes de escrever, para que um erro de
// template não deixe uma resposta pela metade.
func (s *Set) Render(w http.ResponseWriter, status int, page string, data any) error {
	t, ok := s.pages[page]
	if !ok {
		return fmt.Errorf("template %q não existe", page)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		http.Error(w, "erro interno", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, err := buf.WriteTo(w)
	return err
}

func Static() http.Handler {
	sub, _ := fs.Sub(files, "static")
	return http.StripPrefix("/static/", http.FileServerFS(sub))
}
