package webhook

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yahoo/athenz/clients/go/zms"
	v1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	"k8s.io/client-go/tools/cache"
)

var (
	replacer = strings.NewReplacer(".*", ".*", "*", ".*")
)

// roleMappings - cr cache
type roleMappings struct {
	roleToPrincipals map[string][]*simplePrincipal
	roleToAssertion  map[string][]*simpleAssertion
}

// simplePrincipal - principal data
type simplePrincipal struct {
	memberRegex *regexp.Regexp
	expiration  time.Time
}

// simpleAssertion - processed policy
type simpleAssertion struct {
	resource *regexp.Regexp
	action   *regexp.Regexp
	effect   *zms.AssertionEffect
}

// Cache - cache for athenzdomains CR
type Cache struct {
	crIndexInformer cache.SharedIndexInformer
	domainMap       map[string]roleMappings
	lock            sync.RWMutex
}

// NewZpeClient - generate new athenzdomains cr cache
func NewZpeClient(crIndexInformer cache.SharedIndexInformer) *Cache {
	domainMap := make(map[string]roleMappings)
	privateCache := &Cache{
		crIndexInformer: crIndexInformer,
		domainMap:       domainMap,
	}
	crIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.addupdateObj(item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newItem, ok := newObj.(*v1.AthenzDomain)
			if !ok {
				fmt.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.addupdateObj(newItem)
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
	return privateCache
}

// parseData - helper function to parse AthenzDomain data and store it in domainMap
// Important: This function is not thread safe, need to be called with locks around!
func parseData(domainMap map[string]roleMappings, domainName string, item *v1.AthenzDomain) error {
	crMap := domainMap[domainName]
	if item == nil || item.Spec.SignedDomain.Domain == nil || item.Spec.SignedDomain.Domain.Policies == nil || item.Spec.SignedDomain.Domain.Policies.Contents == nil {
		return errors.New("One of AthenzDomain, Domain field in SignedDomain, Domain Policies field or Policies Contents is nil")
	}
	for _, role := range item.Spec.SignedDomain.Domain.Roles {
		if role == nil {
			fmt.Println("Role is nil")
			continue
		}
		_, ok := crMap.roleToPrincipals[string(role.Name)]
		if !ok {
			crMap.roleToPrincipals[string(role.Name)] = []*simplePrincipal{}
		}
		if role.RoleMembers == nil {
			fmt.Println("No role members are found")
			continue
		}
		// Handle trust domains: if string(role.Trust) != ""
		for _, roleMember := range role.RoleMembers {
			if roleMember == nil || roleMember.MemberName == "" {
				fmt.Println("roleMember is nil or MemberName in roleMember is nil")
				continue
			}
			memberRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(string(roleMember.MemberName))) + "$")
			if err != nil {
				fmt.Printf("Error occurred when converting role memeber name into regex format. Error: %v", err)
				continue
			}
			principalData := &simplePrincipal{
				memberRegex: memberRegex,
			}
			if roleMember.Expiration == nil {
				principalData.expiration = time.Time{}
			} else {
				principalData.expiration = roleMember.Expiration.Time
			}
			crMap.roleToPrincipals[string(role.Name)] = append(crMap.roleToPrincipals[string(role.Name)], principalData)
		}
	}

	for _, policy := range item.Spec.SignedDomain.Domain.Policies.Contents.Policies {
		if policy == nil {
			fmt.Println("policy in Contents.Policies is nil")
			continue
		}
		for _, assertion := range policy.Assertions {
			if assertion == nil {
				fmt.Println("assertion in policy.Assertions is nil")
				continue
			}
			_, ok := crMap.roleToAssertion[assertion.Role]
			if !ok {
				crMap.roleToAssertion[assertion.Role] = []*simpleAssertion{}
			}
			effect := assertion.Effect
			resourceRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(assertion.Resource)) + "$")
			if err != nil {
				fmt.Printf("Error occurred when converting assertion resource into regex format. Error: %v", err)
				continue
			}
			actionRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(assertion.Action)) + "$")
			if err != nil {
				fmt.Printf("Error occurred when converting assertion action into regex format. Error: %v", err)
				continue
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

// addupdateObj - add and update cr object in cache
func (c *Cache) addupdateObj(item *v1.AthenzDomain) {
	c.lock.Lock()
	domainName := item.ObjectMeta.Name
	_, ok := c.domainMap[domainName]
	if ok {
		delete(c.domainMap, domainName)
	}
	roleToPrincipals := make(map[string][]*simplePrincipal)
	roleToAssertion := make(map[string][]*simpleAssertion)
	crMap := roleMappings{
		roleToPrincipals: roleToPrincipals,
		roleToAssertion:  roleToAssertion,
	}
	c.domainMap[domainName] = crMap
	parseData(c.domainMap, domainName, item)
	c.lock.Unlock()
}

// deleteObj - delete object in cache
func (c *Cache) deleteObj(item *v1.AthenzDomain) {
	c.lock.Lock()
	domainName := item.ObjectMeta.Name
	_, ok := c.domainMap[domainName]
	if ok {
		delete(c.domainMap, domainName)
	}
	c.lock.Unlock()
}

// authorize - authorize using cache data
func (c *Cache) authorize(principal string, check AthenzAccessCheck) (bool, error) {
	domainName := strings.Split(check.Resource, ":")
	if len(domainName) != 2 {
		return false, errors.New("Error splitting domain name")
	}

	c.lock.RLock()
	defer c.lock.RUnlock()
	crMap := c.domainMap
	domainData, ok := crMap[domainName[0]]
	if !ok {
		return false, fmt.Errorf("%s does not exist in cache map", domainName[0])
	}
	roles := []string{}
	for role, members := range domainData.roleToPrincipals {
		for _, member := range members {
			if member.memberRegex.MatchString(principal) {
				if member.expiration.IsZero() || member.expiration.After(time.Now()) {
					roles = append(roles, role)
				}
			}
		}
	}

	for _, role := range roles {
		policies := domainData.roleToAssertion[role]
		for _, assert := range policies {
			if assert.resource.MatchString(check.Resource) && assert.action.MatchString(check.Action) && *assert.effect == zms.ALLOW {
				return true, nil
			}
		}
	}
	return false, nil
}
