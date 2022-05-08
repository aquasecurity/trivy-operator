package controller

import (
	. "github.com/aquasecurity/trivy-operator/pkg/operator/predicate"

	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ConfigAuditReportReconciler struct {
	logr.Logger
	etc.Config
	trivyoperator.ConfigData
	client.Client
	kube.ObjectResolver
	LimitChecker
	kube.LogsReader
	configauditreport.Plugin
	trivyoperator.PluginContext
	configauditreport.ReadWriter
}

func (r *ConfigAuditReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	resources := []struct {
		kind       kube.Kind
		forObject  client.Object
		ownsObject client.Object
	}{
		{kind: kube.KindPod, forObject: &corev1.Pod{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindReplicaSet, forObject: &appsv1.ReplicaSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindReplicationController, forObject: &corev1.ReplicationController{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindStatefulSet, forObject: &appsv1.StatefulSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindDaemonSet, forObject: &appsv1.DaemonSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindCronJob, forObject: &batchv1beta1.CronJob{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindJob, forObject: &batchv1.Job{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindService, forObject: &corev1.Service{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindConfigMap, forObject: &corev1.ConfigMap{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindRole, forObject: &rbacv1.Role{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindRoleBinding, forObject: &rbacv1.RoleBinding{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
	}

	clusterResources := []struct {
		kind       kube.Kind
		forObject  client.Object
		ownsObject client.Object
	}{
		{kind: kube.KindClusterRole, forObject: &rbacv1.ClusterRole{}, ownsObject: &v1alpha1.ClusterConfigAuditReport{}},
		{kind: kube.KindClusterRoleBindings, forObject: &rbacv1.ClusterRoleBinding{}, ownsObject: &v1alpha1.ClusterConfigAuditReport{}},
		{kind: kube.KindCustomResourceDefinition, forObject: &apiextensionsv1.CustomResourceDefinition{}, ownsObject: &v1alpha1.ClusterConfigAuditReport{}},
	}

	for _, resource := range resources {
		if !r.supportsKind(resource.kind) {
			r.Logger.Info("Skipping unsupported kind", "pluginName", r.PluginContext.GetName(), "kind", resource.kind)
			continue
		}
		err = ctrl.NewControllerManagedBy(mgr).
			For(resource.forObject, builder.WithPredicates(
				Not(ManagedByTrivyOperator),
				Not(IsLeaderElectionResource),
				Not(IsBeingTerminated),
				installModePredicate,
			)).
			Owns(resource.ownsObject).
			Complete(r.reconcileResource(resource.kind))
		if err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.kind, err)
		}
	}

	for _, resource := range clusterResources {
		if !r.supportsKind(resource.kind) {
			r.Logger.Info("Skipping unsupported kind", "pluginName", r.PluginContext.GetName(), "kind", resource.kind)
			continue
		}
		err = ctrl.NewControllerManagedBy(mgr).
			For(resource.forObject, builder.WithPredicates(
				Not(ManagedByTrivyOperator),
				Not(IsBeingTerminated),
			)).
			Owns(resource.ownsObject).
			Complete(r.reconcileResource(resource.kind))
		if err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.kind, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(
			InNamespace(r.Config.Namespace),
			ManagedByTrivyOperator,
			IsConfigAuditReportScan,
			JobHasAnyCondition,
		)).
		Complete(r.reconcileJobs())
}

func (r *ConfigAuditReportReconciler) supportsKind(kind kube.Kind) bool {
	for _, k := range r.Plugin.SupportedKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

func (r *ConfigAuditReportReconciler) reconcileResource(resourceKind kube.Kind) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("kind", resourceKind, "name", req.NamespacedName)

		resourceRef := kube.ObjectRefFromKindAndObjectKey(resourceKind, req.NamespacedName)

		log.V(1).Info("Getting resource from cache")
		resource, err := r.ObjectFromObjectRef(ctx, resourceRef)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached resource that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting %s from cache: %w", resourceKind, err)
		}

		// Skip processing if a resource is a Pod controlled by a built-in K8s workload.
		if resourceKind == kube.KindPod {
			controller := metav1.GetControllerOf(resource)
			if kube.IsBuiltInWorkload(controller) {
				log.V(1).Info("Ignoring managed pod",
					"controllerKind", controller.Kind,
					"controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		if r.Config.ConfigAuditScannerScanOnlyCurrentRevisions && resourceKind == kube.KindReplicaSet {
			controller := metav1.GetControllerOf(resource)
			activeReplicaSet, err := r.IsActiveReplicaSet(ctx, resource, controller)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed checking current revision: %w", err)
			}
			if !activeReplicaSet {
				log.V(1).Info("Ignoring inactive ReplicaSet", "controllerKind", controller.Kind, "controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		// Skip processing if a resource is a Job controlled by CronJob.
		if resourceKind == kube.KindJob {
			controller := metav1.GetControllerOf(resource)
			if controller != nil && controller.Kind == string(kube.KindCronJob) {
				log.V(1).Info("Ignoring managed job", "controllerKind", controller.Kind, "controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		// Skip processing if plugin is not applicable to this object
		applicable, reason, err := r.Plugin.IsApplicable(r.PluginContext, resource)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether plugin is applicable: %w", err)
		}
		if !applicable {
			log.V(1).Info("Pushing back reconcile key",
				"reason", reason,
				"pluginName", r.PluginContext.GetName(),
				"retryAfter", r.ScanJobRetryAfter)
			// TODO Introduce more generic param to retry processing a given key.
			return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
		}

		resourceSpecHash, err := kube.ComputeSpecHash(resource)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("computing spec hash: %w", err)
		}

		pluginConfigHash, err := r.Plugin.ConfigHash(r.PluginContext, kube.Kind(resource.GetObjectKind().GroupVersionKind().Kind))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("computing plugin config hash: %w", err)
		}

		log = log.WithValues("resourceSpecHash", resourceSpecHash, "pluginConfigHash", pluginConfigHash)

		log.V(1).Info("Checking whether configuration audit report exists")
		hasReport, err := r.hasReport(ctx, resourceRef, resourceSpecHash, pluginConfigHash)
		if err != nil {
			return ctrl.Result{}, err
		}

		if hasReport {
			log.V(1).Info("Configuration audit report exists")
			return ctrl.Result{}, nil
		}

		log.V(1).Info("Checking whether configuration audit has been scheduled")
		_, job, err := r.hasActiveScanJob(ctx, resource, resourceSpecHash)
		if err != nil {
			return ctrl.Result{}, err
		}
		if job != nil {
			log.V(1).Info("Configuration audit has been scheduled",
				"job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))
			return ctrl.Result{}, nil
		}

		limitExceeded, scanJobsCount, err := r.LimitChecker.Check(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("Checking scan jobs limit", "count", scanJobsCount, "limit", r.ConcurrentScanJobsLimit)

		if limitExceeded {
			log.V(1).Info("Pushing back reconcile key",
				"reason", "scan jobs limit exceeded",
				"scanJobsCount", scanJobsCount,
				"retryAfter", r.ScanJobRetryAfter)
			return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
		}

		scanJobTolerations, err := r.ConfigData.GetScanJobTolerations()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting scan job tolerations: %w", err)
		}

		scanJobAnnotations, err := r.ConfigData.GetScanJobAnnotations()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting scan job annotations: %w", err)
		}

		scanJobPodTemplateLabels, err := r.GetScanJobPodTemplateLabels()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting scan job template labels: %w", err)
		}

		job, secrets, err := configauditreport.NewScanJobBuilder().
			WithPlugin(r.Plugin).
			WithPluginContext(r.PluginContext).
			WithTimeout(r.Config.ScanJobTimeout).
			WithObject(resource).
			WithTolerations(scanJobTolerations).
			WithAnnotations(scanJobAnnotations).
			WithPodTemplateLabels(scanJobPodTemplateLabels).
			Get()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("constructing scan job: %w", err)
		}

		for _, secret := range secrets {
			err := r.Client.Create(ctx, secret)
			if err != nil {
				if errors.IsAlreadyExists(err) {
					log.V(1).Info("Secret already exists", "secretName", secret.Name)
					return ctrl.Result{}, nil
				}
				return ctrl.Result{}, fmt.Errorf("creating secret: %w", err)
			}
		}

		log.V(1).Info("Scheduling configuration audit", "secrets", len(secrets))
		err = r.Client.Create(ctx, job)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				// TODO Delete secrets that were created in the previous step. Alternatively we can delete them on schedule.
				log.V(1).Info("Job already exists", "jobName", job.Name)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("creating job: %w", err)
		}

		for _, secret := range secrets {
			err := controllerutil.SetOwnerReference(job, secret, r.Client.Scheme())
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("setting owner reference: %w", err)
			}
			err = r.Client.Update(ctx, secret)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("updating secret: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}
}

func (r *ConfigAuditReportReconciler) hasReport(ctx context.Context, owner kube.ObjectRef, podSpecHash string, pluginConfigHash string) (bool, error) {
	if kube.IsClusterScopedKind(string(owner.Kind)) {
		return r.hasClusterReport(ctx, owner, podSpecHash, pluginConfigHash)
	}
	// TODO FindByOwner should accept optional label selector to further narrow down search results
	report, err := r.ReadWriter.FindReportByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		return report.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
			report.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
	}
	return false, nil
}

func (r *ConfigAuditReportReconciler) hasClusterReport(ctx context.Context, owner kube.ObjectRef, podSpecHash string, pluginConfigHash string) (bool, error) {
	report, err := r.ReadWriter.FindClusterReportByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		return report.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
			report.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
	}
	return false, nil
}

func (r *ConfigAuditReportReconciler) hasActiveScanJob(ctx context.Context, obj client.Object, hash string) (bool, *batchv1.Job, error) {
	jobName := configauditreport.GetScanJobName(obj)
	job := &batchv1.Job{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Config.Namespace, Name: jobName}, job)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("getting pod from cache: %w", err)
	}
	if job.Labels[trivyoperator.LabelResourceSpecHash] == hash {
		return true, job, nil
	}
	return false, nil, nil
}

func (r *ConfigAuditReportReconciler) reconcileJobs() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("job", req.NamespacedName)

		job := &batchv1.Job{}
		log.V(1).Info("Getting job from cache")
		err := r.Client.Get(ctx, req.NamespacedName, job)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached job that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
		}

		if len(job.Status.Conditions) == 0 {
			log.V(1).Info("Ignoring job without conditions")
			return ctrl.Result{}, nil
		}

		switch jobCondition := job.Status.Conditions[0].Type; jobCondition {
		case batchv1.JobComplete:
			err = r.processCompleteScanJob(ctx, job)
		case batchv1.JobFailed:
			err = r.processFailedScanJob(ctx, job)
		default:
			err = fmt.Errorf("unrecognized job condition: %v", jobCondition)
		}

		return ctrl.Result{}, err
	}

}

func (r *ConfigAuditReportReconciler) processCompleteScanJob(ctx context.Context, job *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))

	ownerRef, err := kube.ObjectRefFromObjectMeta(job.ObjectMeta)
	if err != nil {
		return fmt.Errorf("getting owner ref from scan job metadata: %w", err)
	}

	owner, err := r.ObjectFromObjectRef(ctx, ownerRef)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Report owner must have been deleted", "owner", owner)
			return r.deleteJob(ctx, job)
		}
		return fmt.Errorf("getting object from object ref: %w", err)
	}

	resourceSpecHash, ok := job.Labels[trivyoperator.LabelResourceSpecHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", trivyoperator.LabelResourceSpecHash)
	}
	pluginConfigHash, ok := job.Labels[trivyoperator.LabelPluginConfigHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", trivyoperator.LabelPluginConfigHash)
	}

	hasReport, err := r.hasReport(ctx, ownerRef, resourceSpecHash, pluginConfigHash)
	if err != nil {
		return err
	}

	if hasReport {
		log.V(1).Info("ConfigAuditReport already exist", "owner", owner)
		log.V(1).Info("Deleting complete scan job", "owner", owner)
		return r.deleteJob(ctx, job)
	}

	logsStream, err := r.LogsReader.GetLogsByJobAndContainerName(ctx, job, r.Plugin.GetContainerName())
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Cached job must have been deleted")
			return nil
		}
		if kube.IsPodControlledByJobNotFound(err) {
			log.V(1).Info("Pod must have been deleted")
			return r.deleteJob(ctx, job)
		}
		return fmt.Errorf("getting logs: %w", err)
	}

	reportData, err := r.Plugin.ParseConfigAuditReportData(r.PluginContext, logsStream)
	defer func() {
		_ = logsStream.Close()
	}()
	if err != nil {
		return err
	}

	reportBuilder := configauditreport.NewReportBuilder(r.Client.Scheme()).
		Controller(owner).
		ResourceSpecHash(resourceSpecHash).
		PluginConfigHash(pluginConfigHash).
		Data(reportData)
	err = reportBuilder.Write(ctx, r.ReadWriter)
	if err != nil {
		return err
	}

	log.V(1).Info("Deleting complete scan job", "owner", owner)
	return r.deleteJob(ctx, job)
}

func (r *ConfigAuditReportReconciler) processFailedScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))

	statuses, err := r.LogsReader.GetTerminatedContainersStatusesByJob(ctx, scanJob)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Cached job must have been deleted")
			return nil
		}
		if kube.IsPodControlledByJobNotFound(err) {
			log.V(1).Info("Pod must have been deleted")
			return r.deleteJob(ctx, scanJob)
		}
		return err
	}
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		log.Error(nil, "Scan job container", "container", container, "status.reason", status.Reason, "status.message", status.Message)
	}
	log.V(1).Info("Deleting failed scan job")
	return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
}

func (r *ConfigAuditReportReconciler) deleteJob(ctx context.Context, job *batchv1.Job) error {
	err := r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("deleting job: %w", err)
	}
	return nil
}
