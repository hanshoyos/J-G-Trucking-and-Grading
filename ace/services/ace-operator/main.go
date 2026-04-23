// ACE Operator — Kubernetes controller for ACE platform CRDs.
//
// Phase 1: Manages IngestPipeline resources (creates/updates ace-ingest Deployments).
// Phase 2+: Will manage CorrelationRule, ThreatIntelFeed, ResponsePlaybook, AssetDiscovery.
package main

import (
	"flag"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	acev1alpha1 "github.com/ace-platform/ace/services/ace-operator/api/v1alpha1"
	"github.com/ace-platform/ace/services/ace-operator/controllers"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(acev1alpha1.AddToScheme(scheme))
	// Register apps/v1 for Deployment ownership
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr         string
		probeAddr           string
		leaderElect         bool
		ingestImageRef      string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Metrics endpoint bind address.")
	flag.StringVar(&probeAddr,   "health-probe-bind-address", ":8081", "Health probe bind address.")
	flag.BoolVar(&leaderElect,   "leader-elect", true, "Enable leader election for HA.")
	flag.StringVar(&ingestImageRef, "ingest-image",
		"ghcr.io/ace-platform/ace-ingest",
		"Container image reference for ace-ingest (tag is set per IngestPipeline).",
	)
	flag.Parse()

	opts := zap.Options{Development: os.Getenv("ACE_DEV_MODE") == "true"}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "ace-operator.ace.platform.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	if err = (&controllers.IngestPipelineReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		ImageRef: ingestImageRef,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to setup IngestPipeline controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("ACE Operator starting",
		"version", version(),
		"leaderElection", leaderElect,
	)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func version() string {
	if v := os.Getenv("ACE_VERSION"); v != "" {
		return v
	}
	return "dev"
}
