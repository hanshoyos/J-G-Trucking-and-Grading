package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ─────────────────────────────────────────────────────────────
//  IngestPipeline — declarative log source configuration CRD
// ─────────────────────────────────────────────────────────────

// IngestPipelineSpec defines the desired state of an IngestPipeline.
type IngestPipelineSpec struct {
	// TenantID scopes all events produced by this pipeline.
	// +kubebuilder:validation:MinLength=1
	TenantID string `json:"tenantId"`

	// CollectorID is a human-readable label for this collector instance.
	// Defaults to the resource name.
	// +optional
	CollectorID string `json:"collectorId,omitempty"`

	// KafkaBrokers is the comma-separated list of Kafka bootstrap brokers.
	// +kubebuilder:validation:MinLength=1
	KafkaBrokers string `json:"kafkaBrokers"`

	// KafkaTopicRaw is the topic raw events are produced to.
	// +kubebuilder:default="ace.events.raw"
	KafkaTopicRaw string `json:"kafkaTopicRaw,omitempty"`

	// KafkaSASL holds optional SASL authentication config.
	// +optional
	KafkaSASL *KafkaSASLConfig `json:"kafkaSasl,omitempty"`

	// Protocols enables/configures individual protocol handlers.
	Protocols ProtocolsSpec `json:"protocols"`

	// Replicas is the desired number of ace-ingest pods for this pipeline.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	Replicas int32 `json:"replicas,omitempty"`

	// Resources sets resource requests/limits for the ingest pods.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// ImageTag overrides the ace-ingest container image tag.
	// +optional
	ImageTag string `json:"imageTag,omitempty"`
}

// KafkaSASLConfig holds SASL authentication parameters.
type KafkaSASLConfig struct {
	// Mechanism is the SASL mechanism (e.g. "PLAIN", "SCRAM-SHA-512").
	Mechanism string `json:"mechanism"`

	// SecretRef references a Kubernetes Secret containing keys
	// "username" and "password".
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// ProtocolsSpec controls which protocol handlers are enabled.
type ProtocolsSpec struct {
	// Syslog enables RFC 5424 / RFC 3164 / CEF / LEEF syslog reception.
	// +optional
	Syslog *SyslogSpec `json:"syslog,omitempty"`

	// Modbus enables Modbus/TCP passive tap.
	// +optional
	Modbus *ModbusSpec `json:"modbus,omitempty"`

	// CloudTrail enables AWS CloudTrail via SQS.
	// +optional
	CloudTrail *CloudTrailSpec `json:"cloudTrail,omitempty"`

	// WEF enables Windows Event Forwarding receiver.
	// +optional
	WEF *WEFSpec `json:"wef,omitempty"`

	// K8sAudit enables Kubernetes audit log webhook receiver.
	// +optional
	K8sAudit *K8sAuditSpec `json:"k8sAudit,omitempty"`
}

// SyslogSpec configures the syslog handler.
type SyslogSpec struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`

	// UDPPort is the UDP port to listen on (default 514).
	// +kubebuilder:default=514
	UDPPort int32 `json:"udpPort,omitempty"`

	// TCPPort is the TCP port to listen on (default 6514).
	// +kubebuilder:default=6514
	TCPPort int32 `json:"tcpPort,omitempty"`
}

// ModbusSpec configures the Modbus/TCP passive tap.
type ModbusSpec struct {
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Port is the TCP port to listen on (default 502).
	// +kubebuilder:default=502
	Port int32 `json:"port,omitempty"`
}

// CloudTrailSpec configures AWS CloudTrail ingestion.
type CloudTrailSpec struct {
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// SQSQueueURL is the SQS queue URL that receives CloudTrail S3 notifications.
	SQSQueueURL string `json:"sqsQueueUrl"`

	// AWSRegion is the AWS region of the SQS queue.
	// +kubebuilder:default="us-east-1"
	AWSRegion string `json:"awsRegion,omitempty"`

	// PollIntervalSeconds is the polling interval in seconds.
	// +kubebuilder:default=10
	PollIntervalSeconds int32 `json:"pollIntervalSeconds,omitempty"`

	// IAMRoleARN is an optional IAM role to assume via IRSA (IAM Roles for Service Accounts).
	// +optional
	IAMRoleARN string `json:"iamRoleArn,omitempty"`
}

// WEFSpec configures the Windows Event Forwarding receiver.
type WEFSpec struct {
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Port is the HTTP port to listen on (default 5985).
	// +kubebuilder:default=5985
	Port int32 `json:"port,omitempty"`
}

// K8sAuditSpec configures the Kubernetes audit webhook receiver.
type K8sAuditSpec struct {
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Port is the HTTP port to listen on (default 9443).
	// +kubebuilder:default=9443
	Port int32 `json:"port,omitempty"`

	// WebhookTokenSecretRef references a Secret with key "token" for
	// bearer-auth on the webhook endpoint.
	// +optional
	WebhookTokenSecretRef *corev1.LocalObjectReference `json:"webhookTokenSecretRef,omitempty"`
}

// ─────────────────────────────────────────────────────────────
//  Status
// ─────────────────────────────────────────────────────────────

// IngestPipelineStatus reflects the observed state of an IngestPipeline.
type IngestPipelineStatus struct {
	// Phase is the high-level lifecycle phase of the pipeline.
	// +kubebuilder:validation:Enum=Pending;Running;Degraded;Failed
	Phase string `json:"phase,omitempty"`

	// ReadyReplicas is the number of ace-ingest pods that are ready.
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Conditions holds detailed status conditions.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration is the .metadata.generation of the spec this status reflects.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// Condition type constants.
const (
	// IngestPipelineConditionReady indicates the pipeline is fully operational.
	IngestPipelineConditionReady = "Ready"
	// IngestPipelineConditionKafkaConnected indicates Kafka connectivity.
	IngestPipelineConditionKafkaConnected = "KafkaConnected"
)

// Phase constants.
const (
	PipelinePhasePending  = "Pending"
	PipelinePhaseRunning  = "Running"
	PipelinePhaseDegraded = "Degraded"
	PipelinePhaseFailed   = "Failed"
)

// ─────────────────────────────────────────────────────────────
//  CRD root types
// ─────────────────────────────────────────────────────────────

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:subresource:scale:specpath=.spec.replicas,statuspath=.status.readyReplicas
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// IngestPipeline is the Schema for the ingestpipelines API.
// It declaratively configures one or more ace-ingest Deployments
// and the protocol handlers they run.
type IngestPipeline struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngestPipelineSpec   `json:"spec,omitempty"`
	Status IngestPipelineStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IngestPipelineList contains a list of IngestPipeline.
type IngestPipelineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngestPipeline `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IngestPipeline{}, &IngestPipelineList{})
}
