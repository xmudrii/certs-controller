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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/xmudrii/certs-controller/pkg/apis/certs/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCABundles implements CABundleInterface
type FakeCABundles struct {
	Fake *FakeCertsV1alpha1
	ns   string
}

var cabundlesResource = schema.GroupVersionResource{Group: "certs.k8s.io", Version: "v1alpha1", Resource: "cabundles"}

var cabundlesKind = schema.GroupVersionKind{Group: "certs.k8s.io", Version: "v1alpha1", Kind: "CABundle"}

// Get takes name of the cABundle, and returns the corresponding cABundle object, and an error if there is any.
func (c *FakeCABundles) Get(name string, options v1.GetOptions) (result *v1alpha1.CABundle, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(cabundlesResource, c.ns, name), &v1alpha1.CABundle{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CABundle), err
}

// List takes label and field selectors, and returns the list of CABundles that match those selectors.
func (c *FakeCABundles) List(opts v1.ListOptions) (result *v1alpha1.CABundleList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(cabundlesResource, cabundlesKind, c.ns, opts), &v1alpha1.CABundleList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.CABundleList{ListMeta: obj.(*v1alpha1.CABundleList).ListMeta}
	for _, item := range obj.(*v1alpha1.CABundleList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested cABundles.
func (c *FakeCABundles) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(cabundlesResource, c.ns, opts))

}

// Create takes the representation of a cABundle and creates it.  Returns the server's representation of the cABundle, and an error, if there is any.
func (c *FakeCABundles) Create(cABundle *v1alpha1.CABundle) (result *v1alpha1.CABundle, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(cabundlesResource, c.ns, cABundle), &v1alpha1.CABundle{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CABundle), err
}

// Update takes the representation of a cABundle and updates it. Returns the server's representation of the cABundle, and an error, if there is any.
func (c *FakeCABundles) Update(cABundle *v1alpha1.CABundle) (result *v1alpha1.CABundle, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(cabundlesResource, c.ns, cABundle), &v1alpha1.CABundle{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CABundle), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCABundles) UpdateStatus(cABundle *v1alpha1.CABundle) (*v1alpha1.CABundle, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(cabundlesResource, "status", c.ns, cABundle), &v1alpha1.CABundle{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CABundle), err
}

// Delete takes name of the cABundle and deletes it. Returns an error if one occurs.
func (c *FakeCABundles) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(cabundlesResource, c.ns, name), &v1alpha1.CABundle{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCABundles) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(cabundlesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.CABundleList{})
	return err
}

// Patch applies the patch and returns the patched cABundle.
func (c *FakeCABundles) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.CABundle, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(cabundlesResource, c.ns, name, data, subresources...), &v1alpha1.CABundle{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CABundle), err
}
