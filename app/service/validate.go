package service

import (
	"errors"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

func unwrap(err error) error {
	for errors.Unwrap(err) != nil {
		err = errors.Unwrap(err)
	}

	return err
}
