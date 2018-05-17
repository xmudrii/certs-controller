/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CABundle is a specification for a CABundle resource
type CABundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CABundleSpec   `json:"spec"`
	Status CABundleStatus `json:"status"`
}

// CABundleSpec is the spec for a CABundle resource
type CABundleSpec struct {
	CSR string `json:"csr"`
}

// CABundleStatus is the status for a CABundle resource
type CABundleStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CABundleList is a list of CABundle resources
type CABundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CABundle `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SrvCert is a specification for a SrvCert resource
type SrvCert struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SrvCertSpec   `json:"spec"`
	Status SrvCertStatus `json:"status"`
}

// SrvCertSpec is the spec for a SrvCert resource
type SrvCertSpec struct {
	CSR string `json:"csr"`
}

// SrvCertStatus is the status for a SrvCert resource
type SrvCertStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SrvCertList is a list of SrvCert resources
type SrvCertList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []SrvCertSpec `json:"items"`
}
