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

	certs_v1alpha1 "github.com/xmudrii/certs-controller/pkg/apis/certs/v1alpha1"
	versioned "github.com/xmudrii/certs-controller/pkg/client/clientset/versioned"
	internalinterfaces "github.com/xmudrii/certs-controller/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/xmudrii/certs-controller/pkg/client/listers/certs/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// CABundleInformer provides access to a shared informer and lister for
// CABundles.
type CABundleInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.CABundleLister
}

type cABundleInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewCABundleInformer constructs a new informer for CABundle type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewCABundleInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredCABundleInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredCABundleInformer constructs a new informer for CABundle type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredCABundleInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertcontrollerV1alpha1().CABundles(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CertcontrollerV1alpha1().CABundles(namespace).Watch(options)
			},
		},
		&certs_v1alpha1.CABundle{},
		resyncPeriod,
		indexers,
	)
}

func (f *cABundleInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredCABundleInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *cABundleInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&certs_v1alpha1.CABundle{}, f.defaultInformer)
}

func (f *cABundleInformer) Lister() v1alpha1.CABundleLister {
	return v1alpha1.NewCABundleLister(f.Informer().GetIndexer())
}