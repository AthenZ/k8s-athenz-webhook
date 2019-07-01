package webhook

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
	v1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	athenzClientset "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned"
	athenzInformer "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/informers/externalversions/athenz/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var (
	replacer = strings.NewReplacer(".*", ".*", "*", ".*")
)

// CRMap - cr cache
type CRMap struct {
	RoleToPrincipals map[string][]*zms.RoleMember
	RoleToAssertion  map[string][]SimpleAssertion
}

// SimpleAssertion - processed policy
type SimpleAssertion struct {
	resource *regexp.Regexp
	action   *regexp.Regexp
	effect   string
}

// Cache - cache for athenzdomains CR
type Cache struct {
	CrIndexInformer cache.SharedIndexInformer
	DomainMap       *map[string]CRMap
}

// BuildCache - generate new athenzdomains cr cache
func BuildCache() (*Cache, error) {
	fmt.Println("Start build cache")
	config := &rest.Config{}
	config.Host = "https://localhost:9999"
	config.CertFile = "/etc/ssl/certs/kube-apiserver.pem"
	config.KeyFile = "/etc/pki/tls/private/kube-apiserver-key.pem"
	config.CAFile = "/etc/ssl/certs/ca.pem"
	clientSet, err := athenzClientset.NewForConfig(config)
	if err != nil {
		fmt.Println("failed to create athenzdomains client")
		return nil, err
	}
	crIndexInformer := athenzInformer.NewAthenzDomainInformer(clientSet, corev1.NamespaceAll, 0, cache.Indexers{})
	domainMap := make(map[string]CRMap)
	crIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
			}
			addObj(domainMap, item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newItem, ok := newObj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
			}
			updateObj(domainMap, newItem)
		},
		DeleteFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
			}
			deleteObj(domainMap, item)
		},
	})
	c := &Cache{
		CrIndexInformer: crIndexInformer,
		DomainMap:       &domainMap,
	}
	return c, nil
}

func parseData(domainMap map[string]CRMap, domainName string, item *v1.AthenzDomain) {
	crMap := domainMap[domainName]
	for _, role := range item.Spec.SignedDomain.Domain.Roles {
		crMap.RoleToPrincipals[string(role.Name)] = role.RoleMembers
	}

	for _, policy := range item.Spec.SignedDomain.Domain.Policies.Contents.Policies {
		for _, assertion := range policy.Assertions {
			_, ok := crMap.RoleToAssertion[assertion.Role]
			if !ok {
				crMap.RoleToAssertion[assertion.Role] = []SimpleAssertion{}
			}
			effect := assertion.Effect.String()
			resourceRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(assertion.Resource)) + "$")
			if err != nil {
				fmt.Printf("Error occurred when converting assertion resource into regex format. Error: %v", err)
			}
			actionRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(assertion.Action)) + "$")
			if err != nil {
				fmt.Printf("Error occurred when converting assertion action into regex format. Error: %v", err)
			}
			simpleAssert := SimpleAssertion{
				resource: resourceRegex,
				action:   actionRegex,
				effect:   effect,
			}
			crMap.RoleToAssertion[assertion.Role] = append(crMap.RoleToAssertion[assertion.Role], simpleAssert)
		}

	}
}

func addObj(domainMap map[string]CRMap, item *v1.AthenzDomain) {
	domainName := item.ObjectMeta.Name
	_, ok := domainMap[domainName]
	if !ok {
		roleToPrincipals := make(map[string][]*zms.RoleMember)
		roleToAssertion := make(map[string][]SimpleAssertion)
		crMap := CRMap{
			RoleToPrincipals: roleToPrincipals,
			RoleToAssertion:  roleToAssertion,
		}
		domainMap[domainName] = crMap
	}
	parseData(domainMap, domainName, item)
}

func updateObj(domainMap map[string]CRMap, item *v1.AthenzDomain) {
	domainName := item.ObjectMeta.Name
	_, ok := domainMap[domainName]
	if ok {
		delete(domainMap, domainName)
	}
	roleToPrincipals := make(map[string][]*zms.RoleMember)
	roleToAssertion := make(map[string][]SimpleAssertion)
	crMap := CRMap{
		RoleToPrincipals: roleToPrincipals,
		RoleToAssertion:  roleToAssertion,
	}
	domainMap[domainName] = crMap
	parseData(domainMap, domainName, item)
}

func deleteObj(domainMap map[string]CRMap, item *v1.AthenzDomain) {
	domainName := item.ObjectMeta.Name
	_, ok := domainMap[domainName]
	if ok {
		delete(domainMap, domainName)
	}
}
