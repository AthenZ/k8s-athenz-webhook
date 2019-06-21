package webhook

import (
	"fmt"

	v1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	athenzClientset "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/clientset/versioned"
	athenzInformer "github.com/yahoo/k8s-athenz-istio-auth/pkg/client/informers/externalversions/athenz/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// CRMap - cr cache
type CRMap struct {
	PrincipalToRoles map[string][]string
	RoleToAssertion  map[string][]SimpleAssertion
}

// SimpleAssertion - simplified policy
type SimpleAssertion struct {
	action   []string
	resource string
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
		for _, member := range role.Members {
			_, ok := crMap.PrincipalToRoles[string(member)]
			if !ok {
				crMap.PrincipalToRoles[string(member)] = []string{}
			}
			crMap.PrincipalToRoles[string(member)] = append(crMap.PrincipalToRoles[string(member)], string(role.Name))
		}
	}

	for _, policy := range item.Spec.SignedDomain.Domain.Policies.Contents.Policies {
		for _, assertion := range policy.Assertions {
			_, ok := crMap.RoleToAssertion[assertion.Role]
			if !ok {
				crMap.RoleToAssertion[assertion.Role] = []SimpleAssertion{}
			}
			// if resource is found in role's list, append the allowed action
			for _, v := range crMap.RoleToAssertion[assertion.Role] {
				effect := *assertion.Effect
				if v.resource == assertion.Resource && effect.String() == "ALLOW" {
					v.action = append(v.action, assertion.Action)
				}
			}
			// if resource is not found, then create new simpleAssertion
			simpleAssert := SimpleAssertion{
				resource: assertion.Resource,
				action:   []string{assertion.Action},
			}
			crMap.RoleToAssertion[assertion.Role] = append(crMap.RoleToAssertion[assertion.Role], simpleAssert)
		}

	}
}

func addObj(domainMap map[string]CRMap, item *v1.AthenzDomain) {
	domainName := item.ObjectMeta.Name
	_, ok := domainMap[domainName]
	if !ok {
		principalToRoles := make(map[string][]string)
		roleToAssertion := make(map[string][]SimpleAssertion)
		crMap := CRMap{
			PrincipalToRoles: principalToRoles,
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
	principalToRoles := make(map[string][]string)
	roleToAssertion := make(map[string][]SimpleAssertion)
	crMap := CRMap{
		PrincipalToRoles: principalToRoles,
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
