package helper

import (
	"encoding/json"
	"os"
	"reflect"

	log "github.com/sirupsen/logrus"
)

// DeepEqual returns a boolean indicating whether the given maps m1 and m2 are equal. First checks
// result according to reflect.DeepEqual(). If not equal, type unification is done by marshalling
// and unmarshalling values, before running same reflect.DeepEqual again. If still not equal,
// returns false.
func DeepEqual(m1, m2 map[string]interface{}) bool {
	if reflect.DeepEqual(m1, m2) {
		return true
	}

	var x1, x2 interface{}
	bytes1, _ := json.Marshal(m1)
	json.Unmarshal(bytes1, &x1)

	bytes2, _ := json.Marshal(m2)
	json.Unmarshal(bytes2, &x2)

	if reflect.DeepEqual(x1, x2) {
		return true
	}

	return false
}

// Getenv works similarly to os.Getenv, but with an extra prefix in the key. If the env variable has
// a value with the prefix, that value is returned. If not, the value of env variable without it
// will be returned.
func Getenv(prefix, key string) string {
	if v := os.Getenv(prefix + key); v != "" {
		return v
	} else {
		return os.Getenv(key)
	}
}

// TransformToArray takes data (type interface{}) and transforms it to slice of strings.
func TransformToArray(data interface{}) []string {
	var output []string

	switch data.(type) {
	case []interface{}:
		for _, val := range data.([]interface{}) {
			if str, ok := val.(string); ok {
				output = append(output, str)
			} else {
				log.Errorf("Could not transform secret key %v to a string", val)
			}
		}
	default:
		log.Errorf("Could not transform secret keys %v to a list", data)
	}

	return output
}
