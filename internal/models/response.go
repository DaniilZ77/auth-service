package models

type Status string

const (
	statusError = "error"
	statusOK    = "ok"
)

type Response struct {
	Status Status `json:"status"`
	Data   any    `json:"data"`
}

func NewErrorResponse(error string) *Response {
	return &Response{
		Status: statusError,
		Data:   error,
	}
}

func NewOKResponse(data any) *Response {
	return &Response{
		Status: statusOK,
		Data:   data,
	}
}
