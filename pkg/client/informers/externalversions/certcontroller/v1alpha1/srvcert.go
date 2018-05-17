/*
Copyright The Kubernetes Authors.

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

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	time "time"

	certcontroller_v1alpha1 "github.com/xmudrii/certs-controller/pkg/apis/certcontroller/v1alpha1"
	versioned "github.com/xmudrii/certs-controller/pkg/client/clientset/versioned"
	internalinterfaces "github.com/xmudrii/certs-controller/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/xmudrii/certs-controller/pkg/client/listers/certcontroller/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// SrvCertInformer provides access to a shared informer and lister for
// SrvCerts.
type SrvCertInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.SrvCertLister
}

type srvCertInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewSrvCertInformer constructs a new informer for SrvCert type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewSrvCertInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredSrvCertInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredSrvCertInformer constructs a new informer for SrvCert type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredSrvCertInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertcontrollerV1alpha1().SrvCerts(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertcontrollerV1alpha1().SrvCerts(namespace).Watch(options)
			},
		},
		&certcontroller_v1alpha1.SrvCert{},
		resyncPeriod,
		indexers,
	)
}

func (f *srvCertInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredSrvCertInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *srvCertInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&certcontroller_v1alpha1.SrvCert{}, f.defaultInformer)
}

func (f *srvCertInformer) Lister() v1alpha1.SrvCertLister {
	return v1alpha1.NewSrvCertLister(f.Informer().GetIndexer())
}
