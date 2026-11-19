package approval

import (
	"encoding/json"
	"fmt"
)

func checkedStringField(value map[string]any, field string) (string, error) {
	text, ok := value[field].(string)
	if !ok {
		return "", fmt.Errorf("Approval answer field %s is invalid. Ask the issuer for a new request.", field)
	}
	return text, nil
}

func checkedIntegerField(value map[string]any, field string) (int64, error) {
	number, ok := value[field].(json.Number)
	if !ok {
		return 0, fmt.Errorf("Approval request field %s is invalid. Ask the issuer for a new request.", field)
	}
	result, err := number.Int64()
	if err != nil {
		return 0, fmt.Errorf("Approval request field %s is outside its integer range. Ask the issuer for a new request.", field)
	}
	return result, nil
}
