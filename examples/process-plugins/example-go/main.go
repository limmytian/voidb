package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

type JsonRpcRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JsonRpcResponse struct {
	JsonRpc string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

type CapabilityError struct {
	Code    int                    `json:"code"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JsonRpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			errResp := JsonRpcResponse{
				JsonRpc: "2.0",
				ID:      nil,
				Error: CapabilityError{
					Code:    -32700,
					Message: "Parse error",
					Data: map[string]interface{}{
						"category":  "transport",
						"code":      "protocol.json_parse_failed",
						"message":   err.Error(),
						"details":   map[string]interface{}{},
						"retryable": false,
						"redaction": "applied",
					},
				},
			}
			out, _ := json.Marshal(errResp)
			fmt.Println(string(out))
			continue
		}

		var resp JsonRpcResponse
		resp.JsonRpc = "2.0"
		resp.ID = req.ID

		switch req.Method {
		case "voidb.initialize":
			resp.Result = map[string]interface{}{
				"plugin_id":        "example-go",
				"protocol_version": "1",
				"status":           "ready",
			}
		case "voidb.health":
			resp.Result = map[string]interface{}{
				"status":             "ready",
				"active_invocations": 0,
				"go_version":         runtime.Version(),
			}
		case "voidb.invoke":
			var params struct {
				Invocation struct {
					ID           string `json:"id"`
					CapabilityID string `json:"capability_id"`
					Input        struct {
						Ping string `json:"ping"`
					} `json:"input"`
				} `json:"invocation"`
			}
			_ = json.Unmarshal(req.Params, &params)

			if params.Invocation.CapabilityID == "info" {
				pong := "pong"
				if params.Invocation.Input.Ping != "" {
					pong = "pong: " + params.Invocation.Input.Ping
				}
				resp.Result = map[string]interface{}{
					"invocation_id": params.Invocation.ID,
					"status":        "succeeded",
					"output": map[string]interface{}{
						"pong":       pong,
						"go_version": runtime.Version(),
					},
					"output_summary": map[string]interface{}{
						"status":    "ok",
						"redaction": "not_required",
					},
				}
			} else {
				resp.Error = CapabilityError{
					Code:    -32040,
					Message: "Capability not found",
					Data: map[string]interface{}{
						"category":  "plugin",
						"code":      "go.capability_not_found",
						"message":   fmt.Sprintf("Capability '%s' not found.", params.Invocation.CapabilityID),
						"details":   map[string]interface{}{},
						"retryable": false,
						"redaction": "applied",
					},
				}
			}
		case "voidb.cancel":
			var params struct {
				InvocationID string `json:"invocation_id"`
			}
			_ = json.Unmarshal(req.Params, &params)
			resp.Result = map[string]interface{}{
				"invocation_id": params.InvocationID,
			}
		default:
			resp.Error = CapabilityError{
				Code:    -32601,
				Message: "Method not found",
				Data: map[string]interface{}{
					"category":  "protocol",
					"code":      "protocol.method_not_found",
					"message":   fmt.Sprintf("Method '%s' not recognized.", req.Method),
					"details":   map[string]interface{}{},
					"retryable": false,
					"redaction": "applied",
				},
			}
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
	}
}
