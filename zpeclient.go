package webhook

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yahoo/athenz/clients/go/zms"
	v1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	lastUpdateKeyField = "latest_contact"
	CacheActive        = true
	CacheStale         = false
)

var (
	replacer = strings.NewReplacer(".*", ".*", "*", ".*")
	// roleReplacer is meant to match regex pattern that athenz supports
	// Refer to: https://github.com/yahoo/athenz/blob/master/clients/java/zpe/src/main/java/com/yahoo/athenz/zpe/AuthZpeClient.java#L764
	roleReplacer = strings.NewReplacer("*", ".*", "?", ".", "^", "\\^", "$", "\\$", ".", "\\.", "|", "\\|", "[", "\\[", "+", "\\+", "\\", "\\\\", "(", "\\(", ")", "\\)", "{", "\\{")
)

// roleMappings - cr cache
type roleMappings struct {
	roleToPrincipals     map[string][]*simplePrincipal
	roleToAllowAssertion map[string][]*simpleAssertion
	roleToDenyAssertion  map[string][]*simpleAssertion
}

// simplePrincipal - principal data
type simplePrincipal struct {
	memberRegex    *regexp.Regexp
	expiration     time.Time
	systemDisabled bool
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
	cmIndexInformer cache.SharedIndexInformer
	domainMap       map[string]roleMappings
	lastUpdate      time.Time
	cacheStatus     bool
	lock            sync.RWMutex
	cmLock          sync.RWMutex
	log             Logger
	maxContactTime  time.Duration
	cacheEnabled    bool
}

// NewZpeClient - generate new athenzdomains cr cache
func NewZpeClient(crIndexInformer cache.SharedIndexInformer, cmIndexInformer cache.SharedIndexInformer, maxContactTime time.Duration, log Logger) *Cache {
	domainMap := make(map[string]roleMappings)
	var lastUpdate time.Time

	privateCache := &Cache{
		crIndexInformer: crIndexInformer,
		cmIndexInformer: cmIndexInformer,
		lastUpdate:      lastUpdate,
		// initalize cache status to stale
		cacheStatus:    CacheStale,
		domainMap:      domainMap,
		maxContactTime: maxContactTime,
		log:            log,
		cacheEnabled:   false,
	}
	crIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				log.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.addOrUpdateObj(item)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newItem, ok := newObj.(*v1.AthenzDomain)
			if !ok {
				log.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.addOrUpdateObj(newItem)
		},
		DeleteFunc: func(obj interface{}) {
			item, ok := obj.(*v1.AthenzDomain)
			if !ok {
				log.Println("Unable to convert informer store item into AthenzDomain type.")
				return
			}
			privateCache.deleteObj(item)
		},
	})
	cmIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			err := privateCache.parseUpdateTime(obj)
			if err != nil {
				log.Println("Unable to convert informer store item into ConfigMap type.")
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			err := privateCache.parseUpdateTime(newObj)
			if err != nil {
				log.Println("Unable to convert informer store item into ConfigMap type.")
				return
			}
		},
	})
	return privateCache
}

// parseData - helper function to parse AthenzDomain data and store it in domainMap
// Important: This function is not thread safe, need to be called with locks around!
func (c *Cache) parseData(item *v1.AthenzDomain) (roleMappings, error) {
	roleToPrincipals := make(map[string][]*simplePrincipal)
	roleToAllowAssertion := make(map[string][]*simpleAssertion)
	roleToDenyAssertion := make(map[string][]*simpleAssertion)
	crMap := roleMappings{
		roleToPrincipals:     roleToPrincipals,
		roleToAllowAssertion: roleToAllowAssertion,
		roleToDenyAssertion:  roleToDenyAssertion,
	}
	if item == nil || item.Spec.SignedDomain.Domain == nil || item.Spec.SignedDomain.Domain.Policies == nil || item.Spec.SignedDomain.Domain.Policies.Contents == nil {
		return crMap, errors.New("One of AthenzDomain, Domain field in SignedDomain, Domain Policies field or Policies Contents is nil")
	}
	for _, role := range item.Spec.SignedDomain.Domain.Roles {
		if role == nil || role.Name == "" {
			c.log.Printf("Role is nil in %s roles", item.Spec.SignedDomain.Domain.Name)
			continue
		}
		roleName := string(role.Name)
		// Handle trust domains: if string(role.Trust) != ""
		// For a trusted domain, role object will only contain following items:
		// modified, name, trust.
		// Note: logic may change depend on how signature validation is implemented.
		if role.Trust != "" {
			var err error
			role.RoleMembers, err = c.processTrustDomain(role.Trust, item, roleName)
			if err != nil {
				c.log.Printf("Error occurred when processing trust domain. Error: %v", err)
				continue
			}
		}

		if role.RoleMembers == nil {
			c.log.Printf("No role members are found in %s", roleName)
			continue
		}

		for _, roleMember := range role.RoleMembers {
			if roleMember == nil || roleMember.MemberName == "" {
				c.log.Println("roleMember is nil or MemberName in roleMember is nil")
				continue
			}
			memberRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(string(roleMember.MemberName))) + "$")
			if err != nil {
				c.log.Printf("Error occurred when converting role memeber name into regex format. Error: %v", err)
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
			if roleMember.SystemDisabled != nil && *roleMember.SystemDisabled != 0 {
				principalData.systemDisabled = true
			}
			_, ok := crMap.roleToPrincipals[roleName]
			if !ok {
				crMap.roleToPrincipals[roleName] = []*simplePrincipal{}
			}
			crMap.roleToPrincipals[roleName] = append(crMap.roleToPrincipals[roleName], principalData)
		}
	}

	for _, policy := range item.Spec.SignedDomain.Domain.Policies.Contents.Policies {
		if policy == nil || len(policy.Assertions) == 0 {
			c.log.Println("policy in Contents.Policies is nil")
			continue
		}
		for _, assertion := range policy.Assertions {
			if assertion == nil || assertion.Role == "" || assertion.Resource == "" || assertion.Action == "" || assertion.Effect == nil {
				c.log.Println("assertion in policy.Assertions is nil")
				continue
			}
			effect := assertion.Effect
			resourceRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(assertion.Resource)) + "$")
			if err != nil {
				c.log.Printf("Error occurred when converting assertion resource into regex format. Error: %v", err)
				continue
			}
			actionRegex, err := regexp.Compile("^" + replacer.Replace(strings.ToLower(assertion.Action)) + "$")
			if err != nil {
				c.log.Printf("Error occurred when converting assertion action into regex format. Error: %v", err)
				continue
			}
			simpleAssert := simpleAssertion{
				resource: resourceRegex,
				action:   actionRegex,
				effect:   effect,
			}
			if *effect == zms.DENY {
				if _, ok := crMap.roleToDenyAssertion[assertion.Role]; !ok {
					crMap.roleToDenyAssertion[assertion.Role] = []*simpleAssertion{}
				}
				crMap.roleToDenyAssertion[assertion.Role] = append(crMap.roleToDenyAssertion[assertion.Role], &simpleAssert)
			} else {
				if _, ok := crMap.roleToAllowAssertion[assertion.Role]; !ok {
					crMap.roleToAllowAssertion[assertion.Role] = []*simpleAssertion{}
				}
				crMap.roleToAllowAssertion[assertion.Role] = append(crMap.roleToAllowAssertion[assertion.Role], &simpleAssert)
			}
		}
	}

	return crMap, nil
}

// processTrustDomain -  in delegated domain check assume_role action in policy that contains current role as a resource, return role's member list
func (c *Cache) processTrustDomain(trust zms.DomainName, item *v1.AthenzDomain, roleName string) ([]*zms.RoleMember, error) {
	var res []*zms.RoleMember
	// handle case which crIndexInformer is not initialized at the beginning, return directly.
	if c.crIndexInformer == nil {
		return res, nil
	}
	trustDomain := string(trust)
	// initialize a clientset to get information of this trust athenz domain
	storage := c.crIndexInformer.GetStore()
	crContent, exists, _ := storage.GetByKey(trustDomain)
	if !exists {
		return res, fmt.Errorf("Error when finding trustDomain %s for this role name %s in the cache: Domain cr is not found in the cache store", trustDomain, roleName)
	}
	// cast it to AthenzDomain object
	obj, ok := crContent.(*v1.AthenzDomain)
	if !ok {
		return res, fmt.Errorf("Error occurred when casting trust domain interface to athen domain object")
	}

	for _, policy := range obj.Spec.SignedDomain.Domain.Policies.Contents.Policies {
		if policy == nil || len(policy.Assertions) == 0 {
			c.log.Println("policy in Contents.Policies is nil")
			continue
		}
		for _, assertion := range policy.Assertions {
			// check if policy contains action "assume_role", and resource matches with delegated role name
			if assertion.Action == "assume_role" {
				// form correct role name
				matched, err := regexp.MatchString("^"+roleReplacer.Replace(assertion.Resource)+"$", roleName)
				if err != nil {
					c.log.Println("string matching failed with err: ", err)
					continue
				}
				if matched {
					delegatedRole := assertion.Role
					// check if above policy's corresponding role is delegated role or not
					for _, role := range obj.Spec.SignedDomain.Domain.Roles {
						if string(role.Name) == delegatedRole {
							if role.Trust != "" {
								// return empty array since athenz zms library does not recursively check delegated domain
								// it only checks one level above. Refer to: https://github.com/yahoo/athenz/blob/master/servers/zms/src/main/java/com/yahoo/athenz/zms/DBService.java#L1972
								return res, nil
							}
							for _, member := range role.RoleMembers {
								res = append(res, member)
							}
							return res, nil
						}
					}
				}
			}
		}
	}
	return res, nil
}

// addupdateObj - add and update cr object in cache
func (c *Cache) addOrUpdateObj(item *v1.AthenzDomain) {
	crMap, err := c.parseData(item)
	if err != nil {
		c.log.Printf("Error happened parsing AthenzDomains CR info. Error: %v", err)
		return
	}
	domainName := item.ObjectMeta.Name
	c.lock.Lock()
	c.domainMap[domainName] = crMap
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
// here logic should be the same as zms access's logic
// Refer to: https://github.com/yahoo/athenz/blob/master/servers/zts/src/main/java/com/yahoo/athenz/zts/ZTSAuthorizer.java#L131
func (c *Cache) authorize(principal string, check AthenzAccessCheck) (bool, error) {
	domainName := strings.Split(check.Resource, ":")
	if len(domainName) < 2 {
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
				if (member.expiration.IsZero() || member.expiration.After(time.Now())) && !member.systemDisabled {
					roles = append(roles, role)
				}
			}
		}
	}
	c.log.Printf("%d roles matched principal: %s on domain: %s", len(roles), principal, domainName[0])

	for _, role := range roles {
		// check if role exists in deny assertion mapping, if exists, deny the check immediately.
		if policies, ok := domainData.roleToDenyAssertion[role]; ok {
			for _, assert := range policies {
				if assert.resource.MatchString(check.Resource) && assert.action.MatchString(check.Action) {
					c.log.Printf("Access denied: assertion has an explict DENY for resource %s and action %s", check.Resource, check.Action)
					return false, nil
				}
			}
		}
		// role doesn't exist in deny assertion mapping, check if there role matches with asertions in roleToAllowAssertion map
		policies := domainData.roleToAllowAssertion[role]
		for _, assert := range policies {
			if assert.resource.MatchString(check.Resource) && assert.action.MatchString(check.Action) {
				c.log.Printf("Access granted: assertion has an explict ALLOW for resource %s and action %s", check.Resource, check.Action)
				return true, nil
			}
		}
	}
	return false, nil
}

// parseUpdateTime - read the last update time as string from configmap, store in the cache
func (c *Cache) parseUpdateTime(configmap interface{}) error {
	var lastUpdateTime string

	obj, ok := configmap.(*corev1.ConfigMap)
	if !ok {
		return fmt.Errorf("Unable to cast interface to config map object")
	}

	// check if lastUpdateKeyField exists in the configmap
	if _, ok = obj.Data[lastUpdateKeyField]; ok {
		lastUpdateTime = strings.ReplaceAll(obj.Data[lastUpdateKeyField], `"`, "")
	} else {
		return fmt.Errorf("configmap format is wrong, it doesn't have a field called: %v", lastUpdateKeyField)
	}
	// update cache status boolean in the cache object
	return c.updateCacheStatus(lastUpdateTime)
}

// updateCacheStatus - read lastUpdate variable, compare with current time and update on cache status
func (c *Cache) updateCacheStatus(timestamp string) error {
	c.cmLock.Lock()
	defer c.cmLock.Unlock()

	if timestamp != "" {
		formatTime, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return fmt.Errorf("timestamp format in syncer config map is wrong")
		}
		c.lastUpdate = formatTime
	}

	t := time.Now()
	t.Format(time.RFC3339Nano)
	diff := t.Sub(c.lastUpdate)
	if diff < c.maxContactTime {
		if c.cacheStatus != CacheActive {
			c.log.Println("cache status change: stale -> active")
		}
		c.cacheStatus = CacheActive
		return nil
	}
	if c.cacheStatus != CacheStale {
		c.log.Println("cache status change: active -> stale")
	}
	c.cacheStatus = CacheStale
	return nil
}

// SetCacheEnabledStatus - sets cacheEnabled value
// when cacheEnabled is set to true, cache will be used in the request flow.
func (c *Cache) SetCacheEnabledStatus(enabled bool) {
	c.log.Printf("set cache enabled status to %t \n", enabled)
	c.cmLock.Lock()
	defer c.cmLock.Unlock()
	c.cacheEnabled = enabled
}
