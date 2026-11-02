package api

import "encoding/json"

// profilesList answers profiles.list with a bare JSON array, never null.
func (h *Handler) profilesList() []ProfileInfo {
	profiles := h.daemon.ProfilesList()
	if profiles == nil {
		profiles = []ProfileInfo{}
	}
	return profiles
}

// invalidProfileParams is the one answer for an undecodable profile request.
// It names no field value: the body may hold a secret.
func invalidProfileParams(id interface{}) *Response {
	return errorResponse(id, ErrCodeInvalidPar, "Invalid params")
}

// profileImport adds a profile and answers {id}. The secret in the request is
// handed to the daemon and goes no further.
func (h *Handler) profileImport(req *Request) *Response {
	var params ProfileImportParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return invalidProfileParams(req.ID)
	}
	id, err := h.daemon.ProfileImport(params)
	if err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, ProfileImportResult{ID: id})
}

// profileUpdate changes a profile and answers {success: true}.
func (h *Handler) profileUpdate(req *Request) *Response {
	var params ProfileUpdateParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.ID == "" {
		return invalidProfileParams(req.ID)
	}
	if err := h.daemon.ProfileUpdate(params); err != nil {
		return mutationErrorResponse(req.ID, err)
	}
	return successResponse(req.ID, SuccessResult{Success: true})
}

// profileByID wraps remove, connect and disconnect, which take {id} and answer
// {success: true}.
func (h *Handler) profileByID(fn func(id string) error) func(*Request) *Response {
	return func(req *Request) *Response {
		var params ProfileIDParams
		if err := json.Unmarshal(req.Params, &params); err != nil || params.ID == "" {
			return invalidProfileParams(req.ID)
		}
		if err := fn(params.ID); err != nil {
			return mutationErrorResponse(req.ID, err)
		}
		return successResponse(req.ID, SuccessResult{Success: true})
	}
}
