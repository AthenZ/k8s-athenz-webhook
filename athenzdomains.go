package webhook

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	v1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	"k8s.io/client-go/tools/cache"
)

var (
	replacer     = strings.NewReplacer(".*", ".*", "*", ".*")
	privateCache *Cache
)

// RoleMappings - cr cache
type roleMappings struct {
	roleToPrincipals map[string][]*regexp.Regexp
	roleToAssertion  map[string][]*simpleAssertion
}

// SimpleAssertion - processed policy
type simpleAssertion struct {
	resource *regexp.Regexp
	action   *regexp.Regexp
	effect   string
}

// Cache - cache for athenzdomains CR
type Cache struct {
	CrIndexInformer cache.SharedIndexInformer
	DomainMap       map[string]roleMappings
	lock            sync.RWMutex
}

// BuildCache - generate new athenzdomains cr cache
func BuildCache(crIndexInformer cache.SharedIndexInformer) {
	domainMap := make(map[string]roleMappings)
	privateCache = &Cache{
		CrIndexInformer: crIndexInformer,
		DomainMap:       domainMap,
	}
	crIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.addObj(item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newItem, ok := newObj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.updateObj(newItem)
		},
		DeleteFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.deleteObj(item)
		},
	})
}

// parseData - helper function to parse AthenzDomain data and store it in domainMap
func parseData(domainMap map[string]roleMappings, domainName string, item *v1.AthenzDomain) error {
	crMap := domainMap[domainName]
	if item == nil || item.Spec.SignedDomain.Domain == nil {
		return errors.New("Some required fields are nil")
	}
	for _, role := range item.Spec.SignedDomain.Domain.Roles {
		if role == nil {
			continue
		}
		_, ok := crMap.roleToPrincipals[string(role.Name)]
		if !ok {
			crMap.roleToPrincipals[string(role.Name)] = []*regexp.Regexp{}
		}
		for _, roleMember := range role.RoleMembers {
			if roleMember == nil {
				continue
			}
			memberRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(string(roleMember.MemberName))) + "$")
			if err != nil {
				fmt.Printf("Error occurred when converting role memeber name into regex format. Error: %v", err)
			}
			crMap.roleToPrincipals[string(role.Name)] = append(crMap.roleToPrincipals[string(role.Name)], memberRegex)
		}
	}

	if item == nil || item.Spec.SignedDomain.Domain == nil || item.Spec.SignedDomain.Domain.Policies == nil || item.Spec.SignedDomain.Domain.Policies.Contents == nil {
		return errors.New("Some required fields are nil")
	}
	for _, policy := range item.Spec.SignedDomain.Domain.Policies.Contents.Policies {
		if policy == nil {
			continue
		}
		for _, assertion := range policy.Assertions {
			if assertion == nil {
				continue
			}
			_, ok := crMap.roleToAssertion[assertion.Role]
			if !ok {
				crMap.roleToAssertion[assertion.Role] = []*simpleAssertion{}
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
			simpleAssert := simpleAssertion{
				resource: resourceRegex,
				action:   actionRegex,
				effect:   effect,
			}
			crMap.roleToAssertion[assertion.Role] = append(crMap.roleToAssertion[assertion.Role], &simpleAssert)
		}
	}
	return nil
}

func (c *Cache) addObj(item *v1.AthenzDomain) {
	c.lock.Lock()
	domainName := item.ObjectMeta.Name
	_, ok := c.DomainMap[domainName]
	if !ok {
		roleToPrincipals := make(map[string][]*regexp.Regexp)
		roleToAssertion := make(map[string][]*simpleAssertion)
		crMap := roleMappings{
			roleToPrincipals: roleToPrincipals,
			roleToAssertion:  roleToAssertion,
		}
		c.DomainMap[domainName] = crMap
	}
	parseData(c.DomainMap, domainName, item)
	c.lock.Unlock()
}

func (c *Cache) updateObj(item *v1.AthenzDomain) {
	c.lock.Lock()
	domainName := item.ObjectMeta.Name
	_, ok := c.DomainMap[domainName]
	if ok {
		delete(c.DomainMap, domainName)
	}
	c.lock.Unlock()
	c.addObj(item)
}

func (c *Cache) deleteObj(item *v1.AthenzDomain) {
	c.lock.Lock()
	domainName := item.ObjectMeta.Name
	_, ok := c.DomainMap[domainName]
	if ok {
		delete(c.DomainMap, domainName)
	}
	c.lock.Unlock()
}

func authorize(principal string, check AthenzAccessCheck) (bool, error) {
	domainName := strings.Split(check.Resource, ":")
	if len(domainName) != 2 {
		return false, errors.New("Error splitting domain name")
	}

	privateCache.lock.RLock()
	defer privateCache.lock.RUnlock()
	crMap := privateCache.DomainMap
	domainData := crMap[domainName[0]]
	roles := []string{}
	for roleName, member := range domainData.roleToPrincipals {
		for _, memberRegex := range member {
			if memberRegex.MatchString(principal) {
				roles = append(roles, roleName)
			}
		}
	}

	for _, r := range roles {
		policies := domainData.roleToAssertion[r]
		for _, assert := range policies {
			if assert.resource.MatchString(check.Resource) && assert.action.MatchString(check.Action) && assert.effect == "ALLOW" {
				return true, nil
			}
		}
	}
	return false, nil
}
