package k8s

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// StatefulSetReplicaReader reads the desired replica count from a
// StatefulSet.
type StatefulSetReplicaReader struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

// NewStatefulSetReplicaReader returns a replica reader.
func NewStatefulSetReplicaReader(client kubernetes.Interface, namespace, statefulSetName string) *StatefulSetReplicaReader {
	return &StatefulSetReplicaReader{client: client, namespace: namespace, name: statefulSetName}
}

// Replicas returns the desired replica count. The second result is false when
// the StatefulSet cannot be read.
func (r *StatefulSetReplicaReader) Replicas(ctx context.Context) (int32, bool) {
	if r == nil || r.client == nil {
		return 0, false
	}
	sts, err := r.client.AppsV1().StatefulSets(r.namespace).Get(ctx, r.name, metav1.GetOptions{})
	if err != nil || sts.Spec.Replicas == nil {
		return 0, false
	}
	return *sts.Spec.Replicas, true
}
