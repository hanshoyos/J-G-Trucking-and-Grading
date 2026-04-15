// Package v1alpha1 contains API types for the ACE platform operator.
//
// The ACE operator manages the lifecycle of ACE log ingestion pipelines,
// correlation rules, threat intelligence feeds, and response playbooks
// as first-class Kubernetes resources (CRDs).
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group and version for ACE resources.
	GroupVersion = schema.GroupVersion{
		Group:   "ace.platform.io",
		Version: "v1alpha1",
	}

	// SchemeBuilder registers the ACE types with a scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme is a shorthand for SchemeBuilder.AddToScheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
