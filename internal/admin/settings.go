package admin

import (
	"net/http"

	"janus/internal/core"
)

type settingsData struct {
	RetentionMonths int
	Database        string
}

func (h *Handler) settings(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	months, err := h.DB.RetentionMonths(r.Context())
	if err != nil {
		return err
	}
	h.render(w, r, http.StatusOK, "settings", page{Title: "Configurações", Admin: &a, Data: settingsData{months, h.DB.Describe()}})
	return nil
}

func (h *Handler) saveSettings(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	months := formInt(r, "retention_months", 0)
	if months < 1 || months > 120 {
		h.render(w, r, http.StatusUnprocessableEntity, "settings", page{Title: "Configurações", Admin: &a,
			Error: "A retenção deve ficar entre 1 e 120 meses.", Data: settingsData{months, h.DB.Describe()}})
		return nil
	}
	if err := h.DB.SetRetentionMonths(r.Context(), months); err != nil {
		return err
	}
	h.audit(r, a, "settings.retention", map[string]int{"months": months})
	redirectSaved(w, r, "/settings")
	return nil
}
