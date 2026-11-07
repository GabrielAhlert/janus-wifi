package admin

import (
	"fmt"
	"net/http"
	"strings"

	"janus/internal/core"
)

// fieldForm alimenta o template "field-form", usado para criar e editar.
type fieldForm struct {
	Field       core.Field
	Types       []core.FieldType
	Protections []core.Protection
}

type fieldsData struct {
	Fields []fieldForm
	New    fieldForm
}

func newFieldForm(f core.Field) fieldForm {
	return fieldForm{Field: f, Types: core.FieldTypes, Protections: core.Protections}
}

func (h *Handler) fields(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	return h.renderFields(w, r, a, s, http.StatusOK, "")
}

func (h *Handler) renderFields(w http.ResponseWriter, r *http.Request, a core.Admin, s core.Site, status int, errMsg string) error {
	list, err := h.DB.Fields(r.Context(), s.ID)
	if err != nil {
		return err
	}
	data := fieldsData{New: newFieldForm(core.Field{Type: core.FieldText, Protection: core.ProtectEncrypted, Enabled: true, Position: (len(list) + 1) * 10})}
	for _, f := range list {
		data.Fields = append(data.Fields, newFieldForm(f))
	}
	h.render(w, r, status, "fields", page{Title: "Campos · " + s.Name, Admin: &a, Site: &s, Tab: "fields", Error: errMsg, Data: data})
	return nil
}

func fieldFromForm(r *http.Request, f core.Field) core.Field {
	f.Label = formText(r, "label")
	f.Placeholder = formText(r, "placeholder")
	f.Purpose = formText(r, "purpose")
	f.Type = core.FieldType(formText(r, "type"))
	f.Protection = core.Protection(formText(r, "protection"))
	f.Required = formBool(r, "required")
	f.Enabled = formBool(r, "enabled")
	f.Position = formInt(r, "position", f.Position)
	return f
}

func (h *Handler) createField(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	f := fieldFromForm(r, core.Field{SiteID: s.ID, Key: strings.ToLower(formText(r, "key"))})
	err = f.Validate()
	if err != nil {
		err = invalid(err)
	} else {
		err = h.DB.CreateField(r.Context(), &f)
	}
	if msg, ok := userError(err, "Já existe um campo com essa chave neste site."); ok {
		return h.renderFields(w, r, a, s, http.StatusUnprocessableEntity, msg)
	} else if err != nil {
		return err
	}
	h.audit(r, a, "field.create", map[string]any{"site": s.ID, "key": f.Key, "protection": f.Protection})
	redirectSaved(w, r, fmt.Sprintf("/sites/%d/fields", s.ID))
	return nil
}

func (h *Handler) updateField(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	fid, err := pathID(r, "fid")
	if err != nil {
		return err
	}
	current, err := h.DB.Field(r.Context(), s.ID, fid)
	if err != nil {
		return err
	}
	f := fieldFromForm(r, current)
	if err := f.Validate(); err != nil {
		return h.renderFields(w, r, a, s, http.StatusUnprocessableEntity, err.Error())
	}
	if err := h.DB.UpdateField(r.Context(), f); err != nil {
		return err
	}
	h.audit(r, a, "field.update", map[string]any{"site": s.ID, "key": f.Key, "protection": f.Protection, "enabled": f.Enabled})
	redirectSaved(w, r, fmt.Sprintf("/sites/%d/fields", s.ID))
	return nil
}

func (h *Handler) deleteField(w http.ResponseWriter, r *http.Request, a core.Admin) error {
	s, err := h.siteFromPath(r)
	if err != nil {
		return err
	}
	fid, err := pathID(r, "fid")
	if err != nil {
		return err
	}
	f, err := h.DB.Field(r.Context(), s.ID, fid)
	if err != nil {
		return err
	}
	if err := h.DB.DeleteField(r.Context(), s.ID, fid); err != nil {
		return err
	}
	h.audit(r, a, "field.delete", map[string]any{"site": s.ID, "key": f.Key})
	redirectSaved(w, r, fmt.Sprintf("/sites/%d/fields", s.ID))
	return nil
}
