package webhook

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/yahoo/athenz/clients/go/zms"
	v1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
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
	DomainMap       map[string]CRMap
	lock            sync.RWMutex
}

// BuildCache - generate new athenzdomains cr cache
func BuildCache(crIndexInformer cache.SharedIndexInformer) *Cache {
	fmt.Println("Start building AthenzDomain map cache")
	domainMap := make(map[string]CRMap)
	c := &Cache{
		CrIndexInformer: crIndexInformer,
		DomainMap:       domainMap,
	}
	crIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
			}
			c.addObj(domainMap, item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newItem, ok := newObj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
			}
			c.updateObj(domainMap, newItem)
		},
		DeleteFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
			}
			c.deleteObj(domainMap, item)
		},
	})
	return c
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

func (c *Cache) addObj(domainMap map[string]CRMap, item *v1.AthenzDomain) {
	c.lock.Lock()
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
	c.lock.Unlock()
}

func (c *Cache) updateObj(domainMap map[string]CRMap, item *v1.AthenzDomain) {
	c.lock.Lock()
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
	c.lock.Unlock()
}

func (c *Cache) deleteObj(domainMap map[string]CRMap, item *v1.AthenzDomain) {
	c.lock.Lock()
	domainName := item.ObjectMeta.Name
	_, ok := domainMap[domainName]
	if ok {
		delete(domainMap, domainName)
	}
	c.lock.Unlock()
}

func (c *Cache) authorize(ctx context.Context, principal string, check AthenzAccessCheck) {
	domainName := strings.Split(check.Resource, ":")
	if len(domainName) != 2 {
		fmt.Println("Error splitting domain name")
	}

	c.lock.RLock()
	crMap := c.DomainMap
	domainData := crMap[domainName[0]]
	roles := []string{}
	for roleName, member := range domainData.RoleToPrincipals {
		for _, m := range member {
			memberRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(string(m.MemberName))) + "$")
			fmt.Println(memberRegex)
			if err != nil {
				fmt.Printf("Error occurred when converting memberNames in roleMember list into regex format. Error: %v", err)
			}
			if memberRegex.MatchString(principal) {
				roles = append(roles, roleName)
			}
		}
	}

	for _, r := range roles {
		policies := domainData.RoleToAssertion[r]
		for _, assert := range policies {
			if assert.resource.MatchString(check.Resource) && assert.action.MatchString(check.Action) && assert.effect == "ALLOW" {
				fmt.Println("Authorization successful using cache data")
			}
		}
	}
	fmt.Println("Authorization failed")
	c.lock.RUnlock()
}
