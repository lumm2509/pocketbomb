package core_test

// The system migrations are registered by the migrations package (it imports core,
// so it can't be imported by core itself): the tests that bootstrap a fresh app
// (core.NewBaseApp + Bootstrap) need them to create the system collections.
import _ "github.com/lumm2509/pocketbomb/migrations"
