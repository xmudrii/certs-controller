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

package certs

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
	certv1alpha1 "github.com/xmudrii/certs-controller/pkg/apis/certs/v1alpha1"
	clientset "github.com/xmudrii/certs-controller/pkg/client/clientset/versioned"
	certscheme "github.com/xmudrii/certs-controller/pkg/client/clientset/versioned/scheme"
	informers "github.com/xmudrii/certs-controller/pkg/client/informers/externalversions"
	listers "github.com/xmudrii/certs-controller/pkg/client/listers/certs/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const controllerAgentName = "certs-controller"

const (
	// SuccessSynced is used as part of the Event 'reason' when a Certificate is synced
	SuccessSynced = "Synced"
	// ErrResourceExists is used as part of the Event 'reason' when a Certificate fails
	// to sync due to a Secret of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Secret already existing
	MessageResourceExists = "Resource %q already exists and is not managed by Certificate"
	// MessageResourceSynced is the message used for an Event fired when a Certificate
	// is synced successfully
	MessageResourceSynced = "Certificate synced successfully"
)

// CertsController is the controller implementation for Certificate resources
type CertsController struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// certclientset is a clientset for our own API group
	certclientset clientset.Interface

	secretsLister      corelisters.SecretLister
	secretsSynced      cache.InformerSynced
	certificateLister  listers.CertificateLister
	certificatesSynced cache.InformerSynced

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

// NewCertsController returns a new cert controller
func NewCertsController(
	kubeclientset kubernetes.Interface,
	certclientset clientset.Interface,
	kubeInformerFactory kubeinformers.SharedInformerFactory,
	certInformerFactory informers.SharedInformerFactory) *CertsController {

	// obtain references to shared index informers for the Secret and Certificate
	// types.
	secretsInformer := kubeInformerFactory.Core().V1().Secrets()
	certificateInformer := certInformerFactory.Certs().V1alpha1().Certificates()

	// Create event broadcaster
	// Add certs-controller types to the default Kubernetes Scheme so Events can be
	// logged for certs-controller types.
	certscheme.AddToScheme(scheme.Scheme)
	glog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	controller := &CertsController{
		kubeclientset:      kubeclientset,
		certclientset:      certclientset,
		secretsLister:      secretsInformer.Lister(),
		secretsSynced:      secretsInformer.Informer().HasSynced,
		certificateLister:  certificateInformer.Lister(),
		certificatesSynced: certificateInformer.Informer().HasSynced,
		workqueue:          workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Certificates"),
		recorder:           recorder,
	}

	glog.Info("Setting up event handlers")
	// Set up an event handler for when Certificate resources change
	certificateInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueCertificate,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueCertificate(new)
		},
	})
	// Set up an event handler for when Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by a Certificate resource will enqueue that Certificate resource for
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
func (c *CertsController) Run(threadiness int, stopCh <-chan struct{}) error {
	defer runtime.HandleCrash()
	defer c.workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	glog.Info("Starting Certificate controller")

	// Wait for the caches to be synced before starting workers
	glog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.secretsSynced, c.certificatesSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	glog.Info("Starting workers")
	// Launch two workers to process Certificate resources
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
func (c *CertsController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *CertsController) processNextWorkItem() bool {
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
		// Certificate resource to be synced.
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
// converge the two. It then updates the Status block of the Certificate resource
// with the current status of the resource.
func (c *CertsController) syncHandler(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the Certificate resource with this namespace/name
	certificate, err := c.certificateLister.Certificates(namespace).Get(name)
	if err != nil {
		// The Certificate resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("certificate '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	secretName := certificate.ObjectMeta.Name
	if secretName == "" {
		// We choose to absorb the error here as the worker would requeue the
		// resource otherwise. Instead, the next time the resource is updated
		// the resource will be queued again.
		runtime.HandleError(fmt.Errorf("%s: secret name must be specified", key))
		return nil
	}

	// Get the secret with the name specified in Certificate.spec
	secret, err := c.secretsLister.Secrets(certificate.Namespace).Get(secretName)
	// If the resource doesn't exist, we'll create it
	if errors.IsNotFound(err) {
		secret, err = c.kubeclientset.CoreV1().Secrets(certificate.Namespace).Create(newSecret(certificate))
	}

	// If an error occurs during Get/Create, we'll requeue the item so we can
	// attempt processing again later. This could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// If the Secret is not controlled by this Certificate resource, we should log
	// a warning to the event recorder and ret
	if !metav1.IsControlledBy(secret, certificate) {
		msg := fmt.Sprintf(MessageResourceExists, secret.Name)
		c.recorder.Event(certificate, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf(msg)
	}

	// If CSR doesn't equal between Spec and Status, update the Secret.
	if certificate.Spec.CSR != "" && bytes.Compare([]byte(certificate.Spec.CSR), secret.Data["csr"]) != 0 {
		glog.V(4).Infof("Certificate %s csr: %s, secret csr: %s", name, certificate.Spec.CSR, string(secret.Data["csr"]))
		secret, err = c.kubeclientset.CoreV1().Secrets(certificate.Namespace).Update(newSecret(certificate))
	}

	// If an error occurs during Update, we'll requeue the item so we can
	// attempt processing again later. THis could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// Finally, we update the status block of the Certificate resource to reflect the
	// current state of the world
	err = c.updateCertificateStatus(certificate, secret)
	if err != nil {
		return err
	}

	c.recorder.Event(certificate, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *CertsController) updateCertificateStatus(certificate *certv1alpha1.Certificate, secret *corev1.Secret) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	certificateCopy := certificate.DeepCopy()

	//certificateCopy.Status.Data = secret.Status.AvailableReplicas

	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the Certificate resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.certclientset.CertsV1alpha1().Certificates(certificate.Namespace).Update(certificateCopy)
	return err
}

// enqueueCertificate takes a Certificate resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Certificate.
func (c *CertsController) enqueueCertificate(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)
}

// handleObject will take any resource implementing metav1.Object and attempt
// to find the Certificate resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that Certificate resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *CertsController) handleObject(obj interface{}) {
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
		// If this object is not owned by a Certificate, we should not do anything more
		// with it.
		if ownerRef.Kind != "Certificate" {
			return
		}

		certificate, err := c.certificateLister.Certificates(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			glog.V(4).Infof("ignoring orphaned object '%s' of certificate '%s'", object.GetSelfLink(), ownerRef.Name)
			return
		}

		c.enqueueCertificate(certificate)
		return
	}
}

// TODO: Check owner references for Secrets.
// newSecret creates a new Secret for a Certificate resource.
func newSecret(certificate *certv1alpha1.Certificate) *corev1.Secret {
	data := make(map[string][]byte)

	data["ca-key.pem"] = []byte("test")

	return &corev1.Secret{
		Data: data,
		ObjectMeta: metav1.ObjectMeta{
			Name:      certificate.ObjectMeta.Name,
			Namespace: certificate.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(certificate, schema.GroupVersionKind{
					Group:   certv1alpha1.SchemeGroupVersion.Group,
					Version: certv1alpha1.SchemeGroupVersion.Version,
					Kind:    "Certificate",
				}),
			},
		},
	}
}