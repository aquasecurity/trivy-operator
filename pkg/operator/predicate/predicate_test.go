package predicate_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	predicatex "sigs.k8s.io/controller-runtime/pkg/predicate"
)

var _ = Describe("Predicate", func() {
	Describe("When checking a InstallMode predicate", func() {
		Context("When install mode is SingleNamespace", func() {
			When("and object is in operator namespace", func() {
				It("Should return false", func() {
					config := etc.Config{
						Namespace:        "trivy-operator",
						TargetNamespaces: "default",
					}
					obj := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "trivy-operator",
						},
					}
					instance, err := predicate.InstallModePredicate(config)
					Expect(err).ToNot(HaveOccurred())

					Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
					Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
					Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
					Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
				})
			})

			When("and object is in target namespace", func() {
				It("Should return true", func() {
					config := etc.Config{
						Namespace:        "trivy-operator",
						TargetNamespaces: "foo",
					}
					obj := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
						},
					}
					instance, err := predicate.InstallModePredicate(config)
					Expect(err).ToNot(HaveOccurred())

					Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
					Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
					Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
					Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
				})
			})
		})

		Context("When install mode is MultiNamespaces", func() {
			When("and object is in target namespace", func() {
				It("Should return true", func() {
					config := etc.Config{
						Namespace:        "trivy-operator",
						TargetNamespaces: "foo,trivy-operator",
					}
					obj := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "trivy-operator",
						},
					}
					instance, err := predicate.InstallModePredicate(config)
					Expect(err).ToNot(HaveOccurred())

					Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
					Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
					Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
					Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
				})
			})

			When("and object is not in target namespace", func() {
				It("Should return false", func() {
					config := etc.Config{
						Namespace:        "trivy-operator",
						TargetNamespaces: "foo,bar",
					}
					obj := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "trivy-operator",
						},
					}
					instance, err := predicate.InstallModePredicate(config)
					Expect(err).ToNot(HaveOccurred())

					Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
					Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
					Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
					Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
				})
			})
		})

		Context("When install mode is AllNamespaces", func() {
			When("and object is not excluded", func() {
				It("Should return true", func() {
					config := etc.Config{
						Namespace:         "trivy-operator",
						TargetNamespaces:  "",
						ExcludeNamespaces: "kube-system",
					}
					obj := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
						},
					}
					instance, err := predicate.InstallModePredicate(config)
					Expect(err).ToNot(HaveOccurred())

					Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
					Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
					Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
					Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
				})
			})

			When("and object is excluded", func() {
				It("Should return false", func() {
					config := etc.Config{
						Namespace:         "trivy-operator",
						TargetNamespaces:  "",
						ExcludeNamespaces: "kube-system,trivyoperator-system",
					}
					obj := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "kube-system",
						},
					}
					instance, err := predicate.InstallModePredicate(config)
					Expect(err).ToNot(HaveOccurred())

					Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
					Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
					Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
					Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
				})
			})

			When("and object is excluded with glob pattern", func() {
				It("Should return false", func() {
					config := etc.Config{
						Namespace:         "trivy-operator",
						TargetNamespaces:  "",
						ExcludeNamespaces: "kube-*,trivyoperator-system",
					}
					obj := &corev1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "kube-system",
						},
					}
					instance, err := predicate.InstallModePredicate(config)
					Expect(err).ToNot(HaveOccurred())

					Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
					Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
					Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
					Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
				})
			})
		})
	})

	Describe("When checking a HasName predicate", func() {
		Context("When object has desired name", func() {
			It("Should return true", func() {
				instance := predicate.HasName("trivyoperator-trivy-config")
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "trivyoperator-trivy-config",
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})

		Context("When object does not have desired name", func() {
			It("Should return false", func() {
				instance := predicate.HasName("trivyoperator-trivy-config")
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "trivyoperator",
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a InNamespace predicate", func() {
		Context("When object is in desired namespace", func() {
			It("Should return true", func() {
				instance := predicate.InNamespace("trivy-operator")
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "trivy-operator",
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})

		Context("When object is not in desired namespace", func() {
			It("Should return false", func() {
				instance := predicate.InNamespace("trivy-operator")
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: corev1.NamespaceDefault,
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a ManagedByTrivyOperator predicate", func() {
		instance := predicate.ManagedByTrivyOperator

		Context("Where object is managed by Trivy-Operator operator", func() {
			It("Should return true", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app.kubernetes.io/managed-by": "trivy-operator",
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})

		Context("Where object is managed by foo app", func() {
			It("Should return false", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app.kubernetes.io/managed-by": "foo",
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})

		Context("Where object is not managed by any app", func() {
			It("Should return false", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a PodBeingTerminated predicate", func() {
		instance := predicate.IsBeingTerminated
		deletionTimestamp := metav1.NewTime(time.Now())

		Context("Where pod is being terminated", func() {
			It("Should return true", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						DeletionTimestamp: &deletionTimestamp,
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})

		Context("Where pod is not being terminated", func() {
			It("Should return false", func() {
				obj := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						DeletionTimestamp: nil,
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a JobHasAnyCondition predicate", func() {
		instance := predicate.JobHasAnyCondition
		Context("Where job has any condition", func() {
			It("Should return true", func() {
				obj := &batchv1.Job{
					Status: batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{
							{
								Type: batchv1.JobComplete,
							},
						},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeTrue())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeTrue())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeTrue())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeTrue())
			})
		})
		Context("Where job doesn't have condition", func() {
			It("Should return false", func() {
				obj := &batchv1.Job{
					Status: batchv1.JobStatus{
						Conditions: []batchv1.JobCondition{},
					},
				}

				Expect(instance.Create(event.CreateEvent{Object: obj})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{ObjectNew: obj})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{Object: obj})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{Object: obj})).To(BeFalse())
			})
		})
	})

	Describe("When checking a Not predicate", func() {
		Context("Where input predicate returns true", func() {
			It("Should return false", func() {
				instance := predicate.Not(predicatex.NewPredicateFuncs(func(_ client.Object) bool {
					return true
				}))

				Expect(instance.Create(event.CreateEvent{})).To(BeFalse())
				Expect(instance.Update(event.UpdateEvent{})).To(BeFalse())
				Expect(instance.Delete(event.DeleteEvent{})).To(BeFalse())
				Expect(instance.Generic(event.GenericEvent{})).To(BeFalse())
			})
		})
	})
})
