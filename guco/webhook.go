package webhook

import (
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	emptyGroupName = "pod-webhook"
)

func SetupWebhookWithManager(mgr manager.Manager, logger logr.Logger) error {

	logger.Info("Registering Webhooks")
	err := RegisterPodImageScanWebhook(mgr)
	if err != nil {
		return err
	}
	return nil
}

func GenerateMutatePath(gvk schema.GroupVersionKind) string {
	groupName := gvk.Group
	if groupName == "" {
		groupName = emptyGroupName
	}

	return "/guco-" + strings.ReplaceAll(groupName, ".", "-") + "-" +
		gvk.Version + "-" + strings.ToLower(gvk.Kind)
}
