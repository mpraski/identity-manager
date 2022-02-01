package identity

import (
	"database/sql/driver"
	"reflect"
	"regexp"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/lindell/go-burner-email-providers/burner"
	"gopkg.in/guregu/null.v4"
)

var (
	Validate      = validator.New()
	passwordRegex = regexp.MustCompile("^[a-zA-Z0-9]+$")
)

func init() {
	Validate.RegisterCustomTypeFunc(validateNullType,
		null.String{},
		null.Time{},
		null.Int{},
		null.Float{},
		null.Bool{},
	)

	if err := Validate.RegisterValidation("burner", func(field validator.FieldLevel) bool {
		return burner.IsBurnerEmail(field.Field().String())
	}); err != nil {
		panic(err)
	}

	if err := Validate.RegisterValidation("password_shape", func(field validator.FieldLevel) bool {
		return passwordRegex.MatchString(field.Field().String())
	}); err != nil {
		panic(err)
	}

	if err := Validate.RegisterValidation("exclude_space", func(field validator.FieldLevel) bool {
		for _, r := range field.Field().String() {
			if unicode.IsSpace(r) {
				return false
			}
		}

		return true
	}); err != nil {
		panic(err)
	}

	if err := Validate.RegisterValidation("exclude_space_around", func(field validator.FieldLevel) bool {
		r := []rune(field.Field().String())
		if len(r) == 0 {
			return true
		}

		return !(unicode.IsSpace(r[0]) || unicode.IsSpace(r[len(r)-1]))
	}); err != nil {
		panic(err)
	}

	if err := Validate.RegisterValidation("past_date", func(field validator.FieldLevel) bool {
		var (
			f = field.Field().Interface()
			n = time.Now().UTC()
		)

		if t, ok := f.(time.Time); ok {
			return t.Equal(n) || t.Before(n)
		}

		return false
	}); err != nil {
		panic(err)
	}

	Validate.RegisterAlias("safe_password", "exclude_space,min=8,max=24,password_shape")
	Validate.RegisterAlias("safe_email", "exclude_space,lowercase,email,burner")
	Validate.RegisterAlias("safe_name", "exclude_space_around,min=2,max=64")
	Validate.RegisterAlias("safe_token", "exclude_space,len=32")
}

func validateNullType(field reflect.Value) interface{} {
	switch t := field.Interface().(type) {
	case null.String, null.Time, null.Int, null.Float, null.Bool:
		if v, ok := t.(driver.Valuer); ok {
			val, err := v.Value()
			if err == nil {
				return val
			}
		}
	}

	return nil
}
