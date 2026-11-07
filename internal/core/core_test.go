package core

import "testing"

func TestNormalizeCPF(t *testing.T) {
	for in, want := range map[string]string{
		"529.982.247-25": "52998224725",
		"52998224725":    "52998224725",
		"529.982.247-24": "",
		"111.111.111-11": "",
		"123":            "",
	} {
		got, err := NormalizeCPF(in)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("NormalizeCPF(%q) = %q, %v; esperado %q", in, got, err, want)
		}
	}
}

func TestFieldNormalize(t *testing.T) {
	tests := []struct {
		field   Field
		in      string
		want    string
		wantErr bool
	}{
		{Field{Label: "E-mail", Type: FieldEmail}, " Ana@Empresa.com.br ", "ana@empresa.com.br", false},
		{Field{Label: "E-mail", Type: FieldEmail}, "ana@", "", true},
		{Field{Label: "Celular", Type: FieldPhone}, "(11) 91234-5678", "11912345678", false},
		{Field{Label: "Celular", Type: FieldPhone}, "1234", "", true},
		{Field{Label: "CPF", Type: FieldCPF}, "529.982.247-25", "52998224725", false},
		{Field{Label: "Nome", Type: FieldText, Required: true}, "  ", "", true},
		{Field{Label: "Nome", Type: FieldText}, "", "", false},
		{Field{Label: "Aceito", Type: FieldCheckbox, Required: true}, "", "", true},
		{Field{Label: "Novidades", Type: FieldCheckbox}, "1", "sim", false},
	}
	for _, tt := range tests {
		got, err := tt.field.Normalize(tt.in)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("%s.Normalize(%q) = %q, %v; esperado %q (erro: %v)", tt.field.Label, tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	for _, in := range []string{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "aabbccddeeff"} {
		if got, err := NormalizeMAC(in); err != nil || got != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("NormalizeMAC(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := NormalizeMAC("zz:bb:cc:dd:ee:ff"); err == nil {
		t.Error("MAC inválido deveria falhar")
	}
}

func TestThemeValidate(t *testing.T) {
	ok := DefaultTheme()
	if err := ok.Validate(); err != nil {
		t.Fatalf("tema padrão inválido: %v", err)
	}
	bad := []func(*Theme){
		func(t *Theme) { t.PrimaryColor = "red" },
		func(t *Theme) { t.CustomCSS = "</style><script>alert(1)</script>" },
		func(t *Theme) { t.RedirectURL = "javascript:alert(1)" },
		func(t *Theme) { t.ButtonText = "" },
	}
	for i, mutate := range bad {
		th := DefaultTheme()
		mutate(&th)
		if th.Validate() == nil {
			t.Errorf("caso %d deveria ser rejeitado", i)
		}
	}
}
