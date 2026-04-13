package wispersgo

//go:generate cargo build --release -p wispers-connect --manifest-path ../../Cargo.toml

/*
#cgo CFLAGS: -I${SRCDIR}/../../wispers-connect/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lwispers_connect
#include "wispers_helpers.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

// NodeState represents the state of a wispers node.
type NodeState int

const (
	NodeStatePending    NodeState = 0
	NodeStateRegistered NodeState = 1
	NodeStateActivated  NodeState = 2
)

func (s NodeState) String() string {
	switch s {
	case NodeStatePending:
		return "Pending"
	case NodeStateRegistered:
		return "Registered"
	case NodeStateActivated:
		return "Activated"
	default:
		return "Unknown"
	}
}

// ActivationStatus represents the activation status of a node in the group.
type ActivationStatus int32

const (
	ActivationUnknown      ActivationStatus = 0
	ActivationNotActivated ActivationStatus = 1
	ActivationActivated    ActivationStatus = 2
)

// GroupState represents the activation state of the connectivity group.
type GroupState int32

const (
	GroupStateAlone          GroupState = 0
	GroupStateBootstrap      GroupState = 1
	GroupStateNeedActivation GroupState = 2
	GroupStateCanEndorse     GroupState = 3
	GroupStateAllActivated   GroupState = 4
)

func (s GroupState) String() string {
	switch s {
	case GroupStateAlone:
		return "Alone"
	case GroupStateBootstrap:
		return "Bootstrap"
	case GroupStateNeedActivation:
		return "NeedActivation"
	case GroupStateCanEndorse:
		return "CanEndorse"
	case GroupStateAllActivated:
		return "AllActivated"
	default:
		return "Unknown"
	}
}

// NodeInfo contains information about a node in the connectivity group.
type NodeInfo struct {
	NodeNumber       int32
	Name             string
	Metadata         string
	IsSelf           bool
	ActivationStatus ActivationStatus
	LastSeenAtMillis int64
	IsOnline         bool
}

// GroupInfo is a snapshot of the connectivity group's activation state.
type GroupInfo struct {
	State GroupState
	Nodes []NodeInfo
}

// RegistrationInfo contains registration information for a node.
type RegistrationInfo struct {
	ConnectivityGroupID string
	NodeNumber          int32
	AuthToken           string
	AttestationJWT      string // Signed JWT attesting to (cg_id, node_number)
}

// initResult is the internal type sent through the bridge channel for RestoreOrInit.
type initResult struct {
	nodePtr unsafe.Pointer
	state   NodeState
}

// startServingResult is the internal type sent through the bridge channel for StartServing.
type startServingResult struct {
	servingPtr  unsafe.Pointer
	sessionPtr  unsafe.Pointer
	incomingPtr unsafe.Pointer
}

// groupInfoResult is the internal type sent through the bridge channel for GroupInfo.
type groupInfoResult struct {
	state GroupState
	nodes []NodeInfo
}

// dataResult is the internal type sent through the bridge channel for data callbacks.
type dataResult struct {
	data []byte
}
