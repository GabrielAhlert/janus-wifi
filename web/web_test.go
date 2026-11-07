package web

import "testing"

func TestLoadParsesEveryPage(t *testing.T) {
	tmpl, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]*Set{"portal": tmpl.Portal, "admin": tmpl.Admin} {
		if _, ok := set.pages["error"]; !ok {
			t.Errorf("%s: página error não foi carregada", name)
		}
	}
}
