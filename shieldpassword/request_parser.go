package shieldpassword

import (
	"encoding/json"
	"net/http"
)

var (
	_ HTTPRequestParser = (*formParser[any])(nil)
	_ HTTPRequestParser = (*jsonParser[any])(nil)
)

// HTTPRequestParser parses HTTP requests to grab user registration and login data.
type HTTPRequestParser interface {
	ParseUserRegistrationData(r *http.Request) (*UserRegistrationData, error)
	ParseUserLoginData(r *http.Request) (*UserLoginData, error)
}

// UserRegistrationData is the form for user login.
type UserRegistrationData struct {
	FirstName string `mod:"trim"`
	LastName  string `mod:"trim"`
	Email     string `mod:"trim" validate:"required,email" scrub:"emails"`
	Password  string `mod:"trim" validate:"required" `
}

// UserLoginData is the form for user login.
type UserLoginData struct {
	Email    string `mod:"trim" validate:"required,email" scrub:"emails"`
	Password string `mod:"trim" validate:"required"`
}

type jsonParser[T any] struct {
	config *HTTPConfig[T]
}

func (p *jsonParser[T]) ParseUserRegistrationData(r *http.Request) (*UserRegistrationData, error) {
	var m map[string]string
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		return nil, err
	}

	return &UserRegistrationData{
		FirstName: m[p.config.FieldFirstName],
		LastName:  m[p.config.FieldLastName],
		Email:     m[p.config.FieldEmail],
		Password:  m[p.config.FieldPassword],
	}, nil
}

func (p *jsonParser[T]) ParseUserLoginData(r *http.Request) (*UserLoginData, error) {
	var m map[string]string
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		return nil, err
	}

	return &UserLoginData{
		Email:    m[p.config.FieldEmail],
		Password: m[p.config.FieldPassword],
	}, nil
}

type formParser[T any] struct {
	config *HTTPConfig[T]
}

func (p *formParser[T]) ParseUserRegistrationData(r *http.Request) (*UserRegistrationData, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return &UserRegistrationData{
		FirstName: r.PostFormValue(p.config.FieldFirstName),
		LastName:  r.PostFormValue(p.config.FieldLastName),
		Email:     r.PostFormValue(p.config.FieldEmail),
		Password:  r.PostFormValue(p.config.FieldPassword),
	}, nil
}

func (p *formParser[T]) ParseUserLoginData(r *http.Request) (*UserLoginData, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return &UserLoginData{
		Email:    r.PostFormValue(p.config.FieldEmail),
		Password: r.PostFormValue(p.config.FieldPassword),
	}, nil
}
