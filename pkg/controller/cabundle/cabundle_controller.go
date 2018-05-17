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

package cabundle

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"bytes"
	"encoding/json"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	certv1alpha1 "github.com/xmudrii/certs-controller/pkg/apis/certs/v1alpha1"
	clientset "github.com/xmudrii/certs-controller/pkg/client/clientset/versioned"
	certscheme "github.com/xmudrii/certs-controller/pkg/client/clientset/versioned/scheme"
	informers "github.com/xmudrii/certs-controller/pkg/client/informers/externalversions"
	listers "github.com/xmudrii/certs-controller/pkg/client/listers/certs/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const controllerAgentName = "cabundle-controller"

const (
	// SuccessSynced is used as part of the Event 'reason' when a CABundle is synced
	SuccessSynced = "Synced"
	// ErrResourceExists is used as part of the Event 'reason' when a CABundle fails
	// to sync due to a Secret of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Secret already existing
	MessageResourceExists = "Resource %q already exists and is not managed by CABundle"
	// MessageResourceSynced is the message used for an Event fired when a CABundle
	// is synced successfully
	MessageResourceSynced = "CABundle synced successfully"
)

// BundleController is the controller implementation for CABundle resources
type BundleController struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// certclientset is a clientset for our own API group
	certclientset clientset.Interface

	secretsLister  corelisters.SecretLister
	secretsSynced  cache.InformerSynced
	caBundleLister listers.CABundleLister
	caBundleSynced cache.InformerSynced

	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	workqueue workqueue.RateLimitingInterface
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}

// NewBundleController returns a new cert controller
func NewBundleController(
	kubeclientset kubernetes.Interface,
	certclientset clientset.Interface,
	kubeInformerFactory kubeinformers.SharedInformerFactory,
	certInformerFactory informers.SharedInformerFactory) *BundleController {

	// obtain references to shared index informers for the Secret and CABundle
	// types.
	secretsInformer := kubeInformerFactory.Core().V1().Secrets()
	caBundleInformer := certInformerFactory.Certcontroller().V1alpha1().CABundles()

	// Create event broadcaster
	// Add certs-controller types to the default Kubernetes Scheme so Events can be
	// logged for certs-controller types.
	certscheme.AddToScheme(scheme.Scheme)
	glog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &BundleController{
		kubeclientset:  kubeclientset,
		certclientset:  certclientset,
		secretsLister:  secretsInformer.Lister(),
		secretsSynced:  secretsInformer.Informer().HasSynced,
		caBundleLister: caBundleInformer.Lister(),
		caBundleSynced: caBundleInformer.Informer().HasSynced,
		workqueue:      workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "CABundles"),
		recorder:       recorder,
	}

	glog.Info("Setting up event handlers")
	// Set up an event handler for when CABundle resources change
	caBundleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueCABundle,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueCABundle(new)
		},
	})
	// Set up an event handler for when Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by a CABundle resource will enqueue that CABundle resource for
	// processing. This way, we don't need to implement custom logic for
	// handling Secret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	secretsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*corev1.Secret)
			oldDepl := old.(*corev1.Secret)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different RVs.
				return
			}
			controller.handleObject(new)
		},
		DeleteFunc: controller.handleObject,
	})

	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *BundleController) Run(threadiness int, stopCh <-chan struct{}) error {
	defer runtime.HandleCrash()
	defer c.workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	glog.Info("Starting CABundle controller")

	// Wait for the caches to be synced before starting workers
	glog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.secretsSynced, c.caBundleSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	glog.Info("Starting workers")
	// Launch two workers to process CABundle resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	glog.Info("Started workers")
	<-stopCh
	glog.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *BundleController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *BundleController) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			runtime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// CABundle resource to be synced.
		if err := c.syncHandler(key); err != nil {
			return fmt.Errorf("error syncing '%s': %s", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.workqueue.Forget(obj)
		glog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		runtime.HandleError(err)
		return true
	}

	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the CABundle resource
// with the current status of the resource.
func (c *BundleController) syncHandler(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the CABundle resource with this namespace/name
	caBundle, err := c.caBundleLister.CABundles(namespace).Get(name)
	if err != nil {
		// The CABundle resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("caBundle '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	secretName := caBundle.ObjectMeta.Name
	if secretName == "" {
		// We choose to absorb the error here as the worker would requeue the
		// resource otherwise. Instead, the next time the resource is updated
		// the resource will be queued again.
		runtime.HandleError(fmt.Errorf("%s: secret name must be specified", key))
		return nil
	}

	// Get the secret with the name specified in CABundle.spec
	secret, err := c.secretsLister.Secrets(caBundle.Namespace).Get(secretName)
	// If the resource doesn't exist, we'll create it
	if errors.IsNotFound(err) {
		secret, err = c.kubeclientset.CoreV1().Secrets(caBundle.Namespace).Create(newSecret(caBundle))
	}

	// If an error occurs during Get/Create, we'll requeue the item so we can
	// attempt processing again later. This could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// If the Secret is not controlled by this CABundle resource, we should log
	// a warning to the event recorder and ret
	if !metav1.IsControlledBy(secret, caBundle) {
		msg := fmt.Sprintf(MessageResourceExists, secret.Name)
		c.recorder.Event(caBundle, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf(msg)
	}

	// If CSR doesn't equal between Spec and Status, update the Secret.
	if caBundle.Spec.CSR != "" && bytes.Compare([]byte(caBundle.Spec.CSR), secret.Data["csr"]) != 0 {
		glog.V(4).Infof("CABundle %s csr: %s, secret csr: %s", name, caBundle.Spec.CSR, string(secret.Data["csr"]))
		secret, err = c.kubeclientset.CoreV1().Secrets(caBundle.Namespace).Update(newSecret(caBundle))
	}

	// If an error occurs during Update, we'll requeue the item so we can
	// attempt processing again later. THis could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// Finally, we update the status block of the CABundle resource to reflect the
	// current state of the world
	err = c.updateCABundleStatus(caBundle, secret)
	if err != nil {
		return err
	}

	c.recorder.Event(caBundle, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *BundleController) updateCABundleStatus(caBundle *certv1alpha1.CABundle, secret *corev1.Secret) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	caBundleCopy := caBundle.DeepCopy()

	//caBundleCopy.Status.Data = secret.Status.AvailableReplicas

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the CABundle resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.certclientset.CertcontrollerV1alpha1().CABundles(caBundle.Namespace).Update(caBundleCopy)
	return err
}

// enqueueCABundle takes a CABundle resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than CABundle.
func (c *BundleController) enqueueCABundle(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)
}

// handleObject will take any resource implementing metav1.Object and attempt
// to find the CABundle resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that CABundle resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *BundleController) handleObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			runtime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
		glog.V(4).Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	}
	glog.V(4).Infof("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		// If this object is not owned by a CABundle, we should not do anything more
		// with it.
		if ownerRef.Kind != "CABundle" {
			return
		}

		caBundle, err := c.caBundleLister.CABundles(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			glog.V(4).Infof("ignoring orphaned object '%s' of caBundle '%s'", object.GetSelfLink(), ownerRef.Name)
			return
		}

		c.enqueueCABundle(caBundle)
		return
	}
}

// TODO: Check owner references for Secrets.
// newSecret creates a new Secret for a CABundle resource.
func newSecret(caBundle *certv1alpha1.CABundle) *corev1.Secret {
	data := make(map[string][]byte)
	cert, pem, key, err := newCAFromCSRBytes([]byte(caBundle.Spec.CSR))
	if err != nil {
		runtime.HandleError(err)
	}
	data["csr"] = []byte(caBundle.Spec.CSR)
	data["ca.pem"] = cert
	data["ca.csr"] = pem
	data["ca-key.pem"] = key

	return &corev1.Secret{
		Data: data,
		ObjectMeta: metav1.ObjectMeta{
			Name:      caBundle.ObjectMeta.Name,
			Namespace: caBundle.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(caBundle, schema.GroupVersionKind{
					Group:   certv1alpha1.SchemeGroupVersion.Group,
					Version: certv1alpha1.SchemeGroupVersion.Version,
					Kind:    "CABundle",
				}),
			},
		},
	}
}

func newCAFromCSRBytes(csrRequest []byte) ([]byte, []byte, []byte, error) {
	caReq := csr.CertificateRequest{
		KeyRequest: csr.NewBasicKeyRequest(),
	}
	err := json.Unmarshal(csrRequest, &caReq)
	if err != nil {
		return nil, nil, nil, err
	}

	return initca.New(&caReq)
}
