// Package controllers implements the reconcile loop for ACE CRDs.
package controllers

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	acev1alpha1 "github.com/ace-platform/ace/services/ace-operator/api/v1alpha1"
)

// ─────────────────────────────────────────────────────────────
//  Reconciler
// ─────────────────────────────────────────────────────────────

// IngestPipelineReconciler reconciles IngestPipeline objects.
type IngestPipelineReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	ImageRef string // e.g. "ghcr.io/ace-platform/ace-ingest"
}

// +kubebuilder:rbac:groups=ace.platform.io,resources=ingestpipelines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ace.platform.io,resources=ingestpipelines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ace.platform.io,resources=ingestpipelines/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *IngestPipelineReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the IngestPipeline resource.
	var pipeline acev1alpha1.IngestPipeline
	if err := r.Get(ctx, req.NamespacedName, &pipeline); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil // Deleted — nothing to do.
		}
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling IngestPipeline",
		"name", pipeline.Name,
		"namespace", pipeline.Namespace,
	)

	// ── ConfigMap ──────────────────────────────────────────────
	if err := r.reconcileConfigMap(ctx, &pipeline); err != nil {
		return ctrl.Result{}, fmt.Errorf("configmap: %w", err)
	}

	// ── Deployment ────────────────────────────────────────────
	if err := r.reconcileDeployment(ctx, &pipeline); err != nil {
		return ctrl.Result{}, fmt.Errorf("deployment: %w", err)
	}

	// ── Service ───────────────────────────────────────────────
	if err := r.reconcileService(ctx, &pipeline); err != nil {
		return ctrl.Result{}, fmt.Errorf("service: %w", err)
	}

	// ── Status update ─────────────────────────────────────────
	return r.updateStatus(ctx, &pipeline)
}

// ─────────────────────────────────────────────────────────────
//  ConfigMap
// ─────────────────────────────────────────────────────────────

func (r *IngestPipelineReconciler) reconcileConfigMap(
	ctx      context.Context,
	pipeline *acev1alpha1.IngestPipeline,
) error {
	desired := r.buildConfigMap(pipeline)
	ctrl.SetControllerReference(pipeline, desired, r.Scheme) //nolint:errcheck

	var existing corev1.ConfigMap
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	existing.Data = desired.Data
	return r.Update(ctx, &existing)
}

func (r *IngestPipelineReconciler) buildConfigMap(
	pipeline *acev1alpha1.IngestPipeline,
) *corev1.ConfigMap {
	protocols := pipeline.Spec.Protocols

	syslogEnabled := "false"
	syslogUDP     := "514"
	syslogTCP     := "6514"
	if protocols.Syslog != nil && protocols.Syslog.Enabled {
		syslogEnabled = "true"
		syslogUDP     = fmt.Sprintf("%d", protocols.Syslog.UDPPort)
		syslogTCP     = fmt.Sprintf("%d", protocols.Syslog.TCPPort)
	}

	modbusEnabled := "false"
	modbusPort    := "502"
	if protocols.Modbus != nil && protocols.Modbus.Enabled {
		modbusEnabled = "true"
		modbusPort    = fmt.Sprintf("%d", protocols.Modbus.Port)
	}

	cloudTrailEnabled := "false"
	cloudTrailSQS     := ""
	if protocols.CloudTrail != nil && protocols.CloudTrail.Enabled {
		cloudTrailEnabled = "true"
		cloudTrailSQS     = protocols.CloudTrail.SQSQueueURL
	}

	wefEnabled := "false"
	wefPort    := "5985"
	if protocols.WEF != nil && protocols.WEF.Enabled {
		wefEnabled = "true"
		wefPort    = fmt.Sprintf("%d", protocols.WEF.Port)
	}

	k8sAuditEnabled := "false"
	k8sAuditPort    := "9443"
	if protocols.K8sAudit != nil && protocols.K8sAudit.Enabled {
		k8sAuditEnabled = "true"
		k8sAuditPort    = fmt.Sprintf("%d", protocols.K8sAudit.Port)
	}

	data := map[string]string{
		"ACE_INGEST__COLLECTOR_ID":   pipeline.Spec.CollectorID,
		"ACE_INGEST__TENANT_ID":      pipeline.Spec.TenantID,
		"ACE_INGEST__KAFKA__BROKERS": pipeline.Spec.KafkaBrokers,

		"ACE_INGEST__PROTOCOLS__SYSLOG__ENABLED":   syslogEnabled,
		"ACE_INGEST__PROTOCOLS__SYSLOG__UDP_PORT":  syslogUDP,
		"ACE_INGEST__PROTOCOLS__SYSLOG__TCP_PORT":  syslogTCP,

		"ACE_INGEST__PROTOCOLS__MODBUS__ENABLED":      modbusEnabled,
		"ACE_INGEST__PROTOCOLS__MODBUS__LISTEN_PORT":  modbusPort,

		"ACE_INGEST__PROTOCOLS__CLOUDTRAIL__ENABLED":       cloudTrailEnabled,
		"ACE_INGEST__PROTOCOLS__CLOUDTRAIL__SQS_QUEUE_URL": cloudTrailSQS,

		"ACE_INGEST__PROTOCOLS__WEF__ENABLED": wefEnabled,
		"ACE_INGEST__PROTOCOLS__WEF__PORT":    wefPort,

		"ACE_INGEST__PROTOCOLS__K8S_AUDIT__ENABLED": k8sAuditEnabled,
		"ACE_INGEST__PROTOCOLS__K8S_AUDIT__PORT":    k8sAuditPort,
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("ace-ingest-%s", pipeline.Name),
			Namespace: pipeline.Namespace,
			Labels:    pipelineLabels(pipeline),
		},
		Data: data,
	}
}

// ─────────────────────────────────────────────────────────────
//  Deployment
// ─────────────────────────────────────────────────────────────

func (r *IngestPipelineReconciler) reconcileDeployment(
	ctx      context.Context,
	pipeline *acev1alpha1.IngestPipeline,
) error {
	desired := r.buildDeployment(pipeline)
	ctrl.SetControllerReference(pipeline, desired, r.Scheme) //nolint:errcheck

	var existing appsv1.Deployment
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	existing.Spec = desired.Spec
	return r.Update(ctx, &existing)
}

func (r *IngestPipelineReconciler) buildDeployment(
	pipeline *acev1alpha1.IngestPipeline,
) *appsv1.Deployment {
	labels   := pipelineLabels(pipeline)
	replicas := pipeline.Spec.Replicas
	if replicas == 0 {
		replicas = 1
	}

	imageTag := pipeline.Spec.ImageTag
	if imageTag == "" {
		imageTag = "latest"
	}
	image := fmt.Sprintf("%s:%s", r.ImageRef, imageTag)

	cmName := fmt.Sprintf("ace-ingest-%s", pipeline.Name)

	res := pipeline.Spec.Resources
	if res.Requests == nil {
		res.Requests = corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		}
	}
	if res.Limits == nil {
		res.Limits = corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("2"),
			corev1.ResourceMemory: resource.MustParse("2Gi"),
		}
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("ace-ingest-%s", pipeline.Name),
			Namespace: pipeline.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"prometheus.io/scrape": "true",
						"prometheus.io/port":   "8080",
						"prometheus.io/path":   "/metrics",
					},
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: boolPtr(true),
						RunAsUser:    int64Ptr(65534),
					},
					Containers: []corev1.Container{
						{
							Name:            "ace-ingest",
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Resources:       res,
							EnvFrom: []corev1.EnvFromSource{
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: cmName,
										},
									},
								},
							},
							Ports: []corev1.ContainerPort{
								{Name: "health",  ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
								{Name: "syslog-udp", ContainerPort: 514, Protocol: corev1.ProtocolUDP},
								{Name: "syslog-tcp", ContainerPort: 6514, Protocol: corev1.ProtocolTCP},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromInt(8080),
									},
								},
								InitialDelaySeconds: 10,
								PeriodSeconds:       15,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz",
										Port: intstr.FromInt(8080),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
							},
						},
					},
				},
			},
		},
	}
}

// ─────────────────────────────────────────────────────────────
//  Service
// ─────────────────────────────────────────────────────────────

func (r *IngestPipelineReconciler) reconcileService(
	ctx      context.Context,
	pipeline *acev1alpha1.IngestPipeline,
) error {
	desired := r.buildService(pipeline)
	ctrl.SetControllerReference(pipeline, desired, r.Scheme) //nolint:errcheck

	var existing corev1.Service
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	existing.Spec.Ports = desired.Spec.Ports
	return r.Update(ctx, &existing)
}

func (r *IngestPipelineReconciler) buildService(
	pipeline *acev1alpha1.IngestPipeline,
) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("ace-ingest-%s", pipeline.Name),
			Namespace: pipeline.Namespace,
			Labels:    pipelineLabels(pipeline),
		},
		Spec: corev1.ServiceSpec{
			Selector: pipelineLabels(pipeline),
			Ports: []corev1.ServicePort{
				{Name: "health",     Port: 8080, Protocol: corev1.ProtocolTCP,  TargetPort: intstr.FromInt(8080)},
				{Name: "syslog-tcp", Port: 6514, Protocol: corev1.ProtocolTCP,  TargetPort: intstr.FromInt(6514)},
				{Name: "syslog-udp", Port: 514,  Protocol: corev1.ProtocolUDP,  TargetPort: intstr.FromInt(514)},
				{Name: "wef",        Port: 5985, Protocol: corev1.ProtocolTCP,  TargetPort: intstr.FromInt(5985)},
				{Name: "k8s-audit",  Port: 9443, Protocol: corev1.ProtocolTCP,  TargetPort: intstr.FromInt(9443)},
			},
		},
	}
}

// ─────────────────────────────────────────────────────────────
//  Status
// ─────────────────────────────────────────────────────────────

func (r *IngestPipelineReconciler) updateStatus(
	ctx      context.Context,
	pipeline *acev1alpha1.IngestPipeline,
) (ctrl.Result, error) {
	var dep appsv1.Deployment
	depName := fmt.Sprintf("ace-ingest-%s", pipeline.Name)
	if err := r.Get(ctx, client.ObjectKey{
		Name:      depName,
		Namespace: pipeline.Namespace,
	}, &dep); err != nil {
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(pipeline.DeepCopy())

	pipeline.Status.ReadyReplicas   = dep.Status.ReadyReplicas
	pipeline.Status.ObservedGeneration = pipeline.Generation

	if dep.Status.ReadyReplicas >= pipeline.Spec.Replicas {
		pipeline.Status.Phase = acev1alpha1.PipelinePhaseRunning
	} else if dep.Status.ReadyReplicas > 0 {
		pipeline.Status.Phase = acev1alpha1.PipelinePhaseDegraded
	} else {
		pipeline.Status.Phase = acev1alpha1.PipelinePhasePending
	}

	return ctrl.Result{}, r.Status().Patch(ctx, pipeline, patch)
}

// ─────────────────────────────────────────────────────────────
//  SetupWithManager
// ─────────────────────────────────────────────────────────────

// SetupWithManager registers the controller with the manager.
func (r *IngestPipelineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&acev1alpha1.IngestPipeline{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

func pipelineLabels(pipeline *acev1alpha1.IngestPipeline) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "ace-ingest",
		"app.kubernetes.io/instance":   pipeline.Name,
		"app.kubernetes.io/managed-by": "ace-operator",
		"ace.platform.io/pipeline":     pipeline.Name,
	}
}

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }
