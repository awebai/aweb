package main

import ()

type creationKeyKind string

const (
	creationKeyKindUnspecified creationKeyKind = ""
	creationKeyKindPerson      creationKeyKind = "person"
	creationKeyKindWorkspace   creationKeyKind = "workspace"
)
