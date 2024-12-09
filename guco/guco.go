package webhook

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/json"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type PodImageScanner struct {
	client  client.Client
	decoder admission.Decoder
	logger  logr.Logger
}

func RegisterPodImageScanWebhook(mgr ctrl.Manager) error {

	m := PodImageScanner{
		client:  mgr.GetClient(),
		decoder: admission.NewDecoder(mgr.GetScheme()),

		logger: mgr.GetLogger(),
	}
	gvk, err := apiutil.GVKForObject(&v1.Pod{}, mgr.GetScheme())
	if err != nil {
		return err
	}
	mgr.GetWebhookServer().Register(GenerateMutatePath(gvk), &webhook.Admission{Handler: &m})
	return nil
}

// Handle implements the admission.Handler interface
func (a *PodImageScanner) Handle(_ context.Context, req admission.Request) admission.Response {

	d := &v1.Pod{}
	a.logger.Info("received request")

	err := a.decoder.Decode(req, d)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	var images []string
	for _, container := range d.Spec.Containers {
		images = append(images, container.Image)
	}

	// add init container
	initContainer, err := getInitContainer(images)

	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	d.Spec.InitContainers = append(d.Spec.InitContainers, initContainer)

	// set restartPolicy to Never
	d.Spec.RestartPolicy = v1.RestartPolicyNever

	//Add Kata-Qemu support
	d.Spec.RuntimeClassName = pointerToString("kata-qemu")

	//container security standards - Not wokring with nginx demo
	// for i := range d.Spec.Containers {
	// 	d.Spec.Containers[i].SecurityContext = &v1.SecurityContext{
	// 		RunAsUser:                pointerToInt64(1000),
	// 		RunAsGroup:               pointerToInt64(1000),
	// 		RunAsNonRoot:             pointerToBool(true),
	// 		Privileged:               pointerToBool(false),
	// 		AllowPrivilegeEscalation: pointerToBool(false),
	// 		Capabilities: &v1.Capabilities{
	// 			Drop: []v1.Capability{"ALL"},
	// 		},
	// 	}
	// 	Read only filesystem failing for nginx demo
	// 	d.Spec.Containers[i].SecurityContext.ReadOnlyRootFilesystem = pointerToBool(true)
	// }

	for i := range d.Spec.InitContainers {
		d.Spec.InitContainers[i].SecurityContext = &v1.SecurityContext{
			RunAsUser:                pointerToInt64(1000),
			RunAsGroup:               pointerToInt64(1000),
			RunAsNonRoot:             pointerToBool(true),
			Privileged:               pointerToBool(false),
			AllowPrivilegeEscalation: pointerToBool(false),
			Capabilities: &v1.Capabilities{
				Drop: []v1.Capability{"ALL"},
			},
		}
		//Read only filesystem
		d.Spec.InitContainers[i].SecurityContext.ReadOnlyRootFilesystem = pointerToBool(true)
	}

	yamlData, err := runtime.Encode(serializer.NewCodecFactory(a.client.Scheme()).LegacyCodec(v1.SchemeGroupVersion), d)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	a.logger.Info("Pod YAML after modification:", "yaml", string(yamlData))

	marshaledPod, err := json.Marshal(d)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)

}

func getInitContainer(images []string) (v1.Container, error) {
	containerCommandTemplate := `
apk add jq;

{{scanCommand}}
`
	scanCommandTemplate := `
snyk container test {{image}}  --severity-threshold=high --json-file-output=/tmp/result.json;
passed=$(jq '.uniqueCount' /tmp/result.json) ;
echo $SNYK_TOKEN;
echo $passed VULNERABILITIES FOUND;
cat /tmp/results.json;
if [ $passed -gt $ALLOWED_VUL ];
then
  exit 1;
fi;
`
	var command string
	var scanCommand []string

	for _, image := range images {

		scanCommand = append(scanCommand, strings.Replace(scanCommandTemplate, "{{image}}", image, -1))
	}

	command = strings.Replace(containerCommandTemplate, "{{scanCommand}}", strings.Join(scanCommand, ""), -1)

	return v1.Container{
		Name:    "guco-preflight",
		Image:   "snyk/snyk:alpine",
		Command: []string{"/bin/sh", "-c"},
		Args:    []string{command},

		Env: []v1.EnvVar{
			{
				Name:  "SNYK_TOKEN",
				Value: os.Getenv("SNYK_TOKEN"),
			},
			{
				Name:  "ALLOWED_VUL",
				Value: os.Getenv("ALLOWED_VUL"),
			},
		},
	}, nil
}

func pointerToString(s string) *string {
	return &s
}

func pointerToInt64(i int64) *int64 {
	return &i
}

func pointerToBool(b bool) *bool {
	return &b
}
