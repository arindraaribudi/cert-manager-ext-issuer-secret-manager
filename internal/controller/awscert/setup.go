package awscertctrl

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// matches returns true only for Certificate events whose IssuerRef points at
// our kind and that carry the ACM ARN annotation. Without the IssuerRef.Group
// guard, any cert-manager Certificate carrying the annotation would wake us.
func (r *IssuerReconciler) matches(obj client.Object) bool {
	c, ok := obj.(*cmapi.Certificate)
	return ok && c.Spec.IssuerRef.Group == "certificates.cert-manager.io" && hasARNAnnotation(obj)
}

func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.Certificate{}, builder.WithPredicates(predicate.NewPredicateFuncs(r.matches))).
		Complete(r)
}