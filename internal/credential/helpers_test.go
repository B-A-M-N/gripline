package credential

import (
	"reflect"
	"strings"
)

// recordFieldNames returns the concatenated field names of CredentialRecord,
// used by the INV-1 assertion that no raw-key field exists.
func recordFieldNames() string {
	typ := reflect.TypeOf(CredentialRecord{})
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, typ.Field(i).Name)
	}
	return strings.Join(names, " ")
}
