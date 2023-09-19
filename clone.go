package auth

import(
	"reflect"
)

func deepClone(src interface{}) interface{} {
	srcValue := reflect.ValueOf(src)
	if srcValue.Kind() != reflect.Ptr || srcValue.IsNil() {
		return nil
	}

	srcType := reflect.TypeOf(src).Elem()
	dst := reflect.New(srcType).Elem()

	for i := 0; i < srcType.NumField(); i++ {
		//field := 
		srcField := srcValue.Elem().Field(i)

		dstField := dst.Field(i)

		if srcField.Kind() == reflect.Ptr && !srcField.IsNil() {
			// Handle pointers
			srcField = srcField.Elem()
			dstField.Set(reflect.New(srcField.Type()))

			// Recursively deep clone the nested value
			deepClonePtr(dstField.Interface(), srcField.Interface())
			//dstField = dstField.Elem()
		} else if srcField.Kind() == reflect.String {
			
			s := reflect.ValueOf(srcValue).Bytes()

				if len(s) == 0 {
					return ""
				}
				b := make([]byte, len(s))
				copy(b, s)
				dstField.SetString(string(s))
			
		} else {
			// For non-pointer fields, simply copy the value
			dstField.Set(srcField)
		}
	}

	return dst.Addr().Interface()
}

func deepClonePtr(dst, src interface{}) {
	dstValue := reflect.ValueOf(dst)
	srcValue := reflect.ValueOf(src)
	

	if dstValue.Kind() == reflect.Ptr && srcValue.Kind() == reflect.Ptr {
		// Recursively deep clone the referenced values
		dstValue.Elem().Set(reflect.ValueOf(deepClone(srcValue.Elem().Interface())))
	}
}

func clone[T any](src T) T {
	x := deepClone(src).(T)
	return x
}