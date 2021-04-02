package webhook

import (
	"log"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/stretchr/testify/assert"
	"github.com/yahoo/athenz/clients/go/zms"
	v1 "github.com/yahoo/k8s-athenz-syncer/pkg/apis/athenz/v1"
	"github.com/yahoo/k8s-athenz-syncer/pkg/client/clientset/versioned/fake"
	athenzInformer "github.com/yahoo/k8s-athenz-syncer/pkg/client/informers/externalversions/athenz/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
)

const (
	domainName      = "home.domain"
	username        = "user.name"
	trustDomainName = "test.trust.domain"
	trustusername   = "trustuser.name"
	domainWithDeny  = "home.domain.deny"
)

var (
	ad = &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainName,
		},
		Spec: v1.AthenzDomainSpec{
			SignedDomain: getFakeDomain(),
		},
	}
	ad1 = &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: trustDomainName,
		},
		Spec: v1.AthenzDomainSpec{
			SignedDomain: getFakeTrustDomain(),
		},
	}

	cm0 = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cm",
		},
		Data: map[string]string{
			"latest_contact": "wrong time format",
		},
	}
	cm = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cm",
		},
		Data: map[string]string{
			"latest_contact": time.Now().Format(time.RFC3339Nano),
		},
	}

	cm1 = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cm1",
		},
		Data: map[string]string{
			"latest_contact": "2020-02-11T17:44:38.080Z",
		},
	}
)

func getFakeAthenzDomain() *v1.AthenzDomain {
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeDomain(),
	}
	item := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainName,
		},
		Spec: spec,
	}
	return item
}

func getFakeDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-06-21T19:28:09.305Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     zms.DomainName(domainName),
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: zms.DomainName(domainName),
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainName + ":role.admin",
									Resource: domainName + ":*",
									Action:   "*",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainName + ":policy.admin"),
						},
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainName + ":role.delegated",
									Resource: domainName + ":services",
									Action:   "create",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainName + ":policy.delegated"),
						},
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainName + ":role.invaliduser",
									Resource: domainName + ":*",
									Action:   "*",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainName + ":policy.invaliduser"),
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{zms.MemberName(username)},
					Modified: &timestamp,
					Name:     zms.ResourceName(domainName + ":role.admin"),
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: zms.MemberName(username),
						},
					},
				},
				{
					Name:  zms.ResourceName(domainName + ":role.delegated"),
					Trust: trustDomainName,
				},
				{
					Name:  zms.ResourceName(domainName + ":role.invaliduser"),
					Trust: trustDomainName,
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}

func getFakeTrustAthenzDomain() *v1.AthenzDomain {
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeTrustDomain(),
	}
	item := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: trustDomainName,
		},
		Spec: spec,
	}
	return item
}

func getFakeTrustDomain() zms.SignedDomain {
	allow := zms.ALLOW
	timestamp, err := rdl.TimestampParse("2019-07-22T20:29:10.305Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     zms.DomainName(trustDomainName),
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: zms.DomainName(trustDomainName),
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     trustDomainName + ":role.admin",
									Resource: "*:role.delegated",
									Action:   "assume_role",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(trustDomainName + ":policy.admin"),
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{zms.MemberName(trustusername)},
					Modified: &timestamp,
					Name:     zms.ResourceName(trustDomainName + ":role.admin"),
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: zms.MemberName(trustusername),
						},
					},
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}

func getFakeAthenzDomainWithExplicitDeny() *v1.AthenzDomain {
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeDomainWithExplicitDeny(),
	}
	item := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainWithDeny,
		},
		Spec: spec,
	}
	return item
}

func getFakeDomainWithExplicitDeny() zms.SignedDomain {
	allow := zms.ALLOW
	deny := zms.DENY
	timestamp, err := rdl.TimestampParse("2020-02-17T20:29:10.305Z")
	if err != nil {
		panic(err)
	}

	return zms.SignedDomain{
		Domain: &zms.DomainData{
			Modified: timestamp,
			Name:     zms.DomainName(domainWithDeny),
			Policies: &zms.SignedPolicies{
				Contents: &zms.DomainPolicies{
					Domain: zms.DomainName(domainWithDeny),
					Policies: []*zms.Policy{
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainWithDeny + ":role.admin",
									Resource: domainWithDeny + ":*",
									Action:   "*",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainWithDeny + ":policy.admin"),
						},
						{
							Assertions: []*zms.Assertion{
								{
									Role:     domainWithDeny + ":role.admin",
									Resource: domainWithDeny + ":services",
									Action:   "delete",
									Effect:   &deny,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainWithDeny + ":policy.admin"),
						},
					},
				},
				KeyId:     "col-env-1.1",
				Signature: "signature-policy",
			},
			Roles: []*zms.Role{
				{
					Members:  []zms.MemberName{zms.MemberName(username)},
					Modified: &timestamp,
					Name:     zms.ResourceName(domainWithDeny + ":role.admin"),
					RoleMembers: []*zms.RoleMember{
						{
							MemberName: zms.MemberName(username),
						},
					},
				},
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}

func newCache() *Cache {
	domainMap := make(map[string]roleMappings)
	athenzclientset := fake.NewSimpleClientset()
	crIndexInformer := athenzInformer.NewAthenzDomainInformer(athenzclientset, 0, cache.Indexers{})
	k8sclientset := fake.NewSimpleClientset()
	cmListWatcher := cache.NewListWatchFromClient(k8sclientset.AthenzV1().RESTClient(), "", "", fields.Everything())
	cmIndexInformer := cache.NewSharedIndexInformer(cmListWatcher, &corev1.ConfigMap{}, time.Hour, cache.Indexers{})
	c := &Cache{
		crIndexInformer: crIndexInformer,
		cmIndexInformer: cmIndexInformer,
		domainMap:       domainMap,
		log:             log.New(os.Stderr, "", log.LstdFlags),
	}
	roleToPrincipals := make(map[string][]*simplePrincipal)
	roleToAllowAssertion := make(map[string][]*simpleAssertion)
	roleToDenyAssertion := make(map[string][]*simpleAssertion)
	crMap := roleMappings{
		roleToPrincipals:     roleToPrincipals,
		roleToAllowAssertion: roleToAllowAssertion,
		roleToDenyAssertion:  roleToDenyAssertion,
	}
	c.crIndexInformer.GetStore().Add(ad.DeepCopy())
	c.crIndexInformer.GetStore().Add(ad1.DeepCopy())
	c.cmIndexInformer.GetStore().Add(cm.DeepCopy())
	c.cmIndexInformer.GetStore().Add(cm1.DeepCopy())

	c.domainMap[domainName] = crMap
	c.domainMap[trustDomainName] = crMap
	return c
}

func TestParseData(t *testing.T) {
	c := newCache()
	// load fake trust domain object
	item := getFakeTrustAthenzDomain()
	crMap, err := c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	// if the map creation fails, report error
	if len(crMap.roleToPrincipals) != 1 || crMap.roleToPrincipals[trustDomainName+":role.admin"] == nil {
		t.Error("Failed to create RoleToPrincipals map")
	}
	item = getFakeAthenzDomain()
	crMap, err = c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	// if trust domain exist, it will pull the members from the delegated role
	if len(crMap.roleToPrincipals) != 2 || crMap.roleToPrincipals["home.domain:role.admin"] == nil || crMap.roleToPrincipals["home.domain:role.delegated"] == nil {
		t.Error("Failed to create RoleToPrincipals map")
	}

	if len(crMap.roleToAllowAssertion) != 3 || crMap.roleToPrincipals["home.domain:role.admin"] == nil || crMap.roleToPrincipals["home.domain:role.delegated"] == nil {
		t.Error("Failed to create RoleToAssertion map")
	}
}

func TestParseDataNilCase(t *testing.T) {
	c := newCache()
	item := getFakeAthenzDomain()
	item.Spec.SignedDomain.Domain.Policies.Contents = nil
	_, err := c.parseData(item)
	if err.Error() != "One of AthenzDomain, Domain field in SignedDomain, Domain Policies field or Policies Contents is nil" {
		t.Error("did not catch policies content nil")
	}

	item.Spec.SignedDomain.Domain.Policies = nil
	_, err = c.parseData(item)
	if err.Error() != "One of AthenzDomain, Domain field in SignedDomain, Domain Policies field or Policies Contents is nil" {
		t.Error("did not catch policies nil")
	}

	item.Spec.SignedDomain.Domain = nil
	_, err = c.parseData(item)
	if err.Error() != "One of AthenzDomain, Domain field in SignedDomain, Domain Policies field or Policies Contents is nil" {
		t.Error("did not catch Domain data nil")
	}

	_, err = c.parseData(nil)
	if err.Error() != "One of AthenzDomain, Domain field in SignedDomain, Domain Policies field or Policies Contents is nil" {
		t.Error("did not catch item nil")
	}
}

func TestParseDataPrincipal(t *testing.T) {
	c := newCache()
	item := getFakeAthenzDomain()

	// role has nil field or empty object
	item.Spec.SignedDomain.Domain.Roles = []*zms.Role{
		{},
		nil,
	}
	crmap, err := c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	if len(crmap.roleToPrincipals) != 0 {
		t.Error("roleToPrincipal map should be empty since roles are empty or nil")
	}

	// roleMember is nil or roleMember name is nil
	item.Spec.SignedDomain.Domain.Roles = []*zms.Role{
		{
			Members: []zms.MemberName{zms.MemberName(username)},
			Name:    zms.ResourceName(domainName + ":role.admin"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName(""),
				},
			},
		},
		{
			Members: []zms.MemberName{zms.MemberName(username)},
			Name:    zms.ResourceName(domainName + ":role.admin"),
			RoleMembers: []*zms.RoleMember{
				{},
				nil,
			},
		},
	}
	crmap, err = c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	if len(crmap.roleToPrincipals["home.domain:role.admin"]) != 0 {
		t.Error("roleToPrincipal array should be empty since role members are empty")
	}

	// regex conversion fail
	item.Spec.SignedDomain.Domain.Roles = []*zms.Role{
		{
			Members: []zms.MemberName{zms.MemberName(username)},
			Name:    zms.ResourceName(domainName + ":role.admin"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName("/?([a-zA-Z0-9_+-\\s+]+)"),
				},
			},
		},
	}
	crmap, err = c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	if len(crmap.roleToPrincipals["home.domain:role.admin"]) != 0 {
		t.Error("member shouldn't be added to the map because member name regex is invalid")
	}
}

func TestParseDataPolicy(t *testing.T) {
	c := newCache()
	item := getFakeAthenzDomain()

	// policy is nil
	item.Spec.SignedDomain.Domain.Policies.Contents.Policies = []*zms.Policy{
		{},
		nil,
	}
	crmap, err := c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	if len(crmap.roleToAllowAssertion) != 0 {
		t.Error("map entries shouldn't be added because policies are nil or empty")
	}

	// assertion is nil
	item.Spec.SignedDomain.Domain.Policies.Contents.Policies = []*zms.Policy{
		{
			Assertions: []*zms.Assertion{
				{},
				nil,
			},
			Name: zms.ResourceName(domainName + ":policy.admin"),
		},
	}
	crmap, err = c.parseData(item)
	if err != nil {
		t.Error(err)
	}
	if len(crmap.roleToAllowAssertion) != 0 {
		t.Error("map entries shouldn't be added because assertions are nil or empty")
	}
}

func TestAddOrUpdateObj(t *testing.T) {
	c := newCache()
	item := getFakeAthenzDomain()

	// add athenz domain
	c.addOrUpdateObj(item)
	obj, ok := c.domainMap[domainName]
	if !ok {
		t.Error("Failed to add AthenzDomain to domainMap")
	}
	if len(obj.roleToPrincipals["home.domain:role.admin"]) != 1 {
		t.Error("Failed to add AthenzDomain to domainMap. RoleToPrincipals is empty.")
	}
	targetRegex, err := regexp.Compile("^user.name$")
	if err != nil {
		t.Error(err)
	}
	actualRegex := obj.roleToPrincipals["home.domain:role.admin"][0].memberRegex
	if actualRegex.String() != targetRegex.String() {
		t.Error("member added to the map does not match target regex")
	}

	// update athenz domains
	item.Spec.Domain.Roles = []*zms.Role{
		{
			Members: []zms.MemberName{zms.MemberName(username)},
			Name:    zms.ResourceName(domainName + ":role.admin.test1"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName(username),
					Expiration: &rdl.Timestamp{
						Time: time.Now().Add(time.Hour),
					},
				},
			},
		},
		{
			Members: []zms.MemberName{zms.MemberName(username + "1")},
			Name:    zms.ResourceName(domainName + ":role.admin.test2"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName(username),
					Expiration: &rdl.Timestamp{
						Time: time.Now().Add(2 * time.Hour),
					},
				},
			},
		},
	}
	c.addOrUpdateObj(item)
	crMap, ok := c.domainMap[domainName]
	if !ok {
		t.Error("Failed to keep AthenzDomain to domainMap")
	}
	if len(crMap.roleToPrincipals) != 2 {
		t.Error("Failed to update AthenzDomain roles")
	}
	if crMap.roleToPrincipals["home.domain:role.admin.test1"][0].memberRegex.String() != targetRegex.String() {
		t.Error("Unable to find correct member for role home.domain:role.admin.test1")
	}
	if crMap.roleToPrincipals["home.domain:role.admin.test2"][0].memberRegex.String() != targetRegex.String() {
		t.Error("Unable to find correct member for role home.domain:role.admin.test2")
	}
}

func TestDeleteObj(t *testing.T) {
	c := newCache()
	item := getFakeAthenzDomain()
	c.deleteObj(item)
	_, ok := c.domainMap[domainName]
	if ok {
		t.Error("Failed to delete AthenzDomain in domainMap")
	}
}

func TestAuthorize(t *testing.T) {
	privateCache := newCache()
	item := getFakeAthenzDomain()
	crMap, err := privateCache.parseData(item)
	if err != nil {
		t.Error(err)
	}
	privateCache.domainMap[domainName] = crMap
	item = getFakeTrustAthenzDomain()
	crMap, err = privateCache.parseData(item)
	if err != nil {
		t.Error(err)
	}
	privateCache.domainMap[trustDomainName] = crMap
	item = getFakeAthenzDomainWithExplicitDeny()
	crMap, err = privateCache.parseData(item)
	if err != nil {
		t.Error(err)
	}
	privateCache.domainMap[domainWithDeny] = crMap

	// grant access
	check := AthenzAccessCheck{
		Action:   "get",
		Resource: "home.domain:pods",
	}
	res, err := privateCache.authorize(username, check)
	if err != nil {
		t.Error(err)
	}
	if !res {
		t.Error("Wrong authorization result, authorization should pass.")
	}

	// deny trust role members access
	res, err = privateCache.authorize(trustusername, check)
	if err != nil {
		t.Error(err)
	}
	if res {
		t.Error("Wrong authorization result, authorization should not pass because trustuser only has access to create services.")
	}

	// grant trust role members access
	check = AthenzAccessCheck{
		Action:   "create",
		Resource: "home.domain:services",
	}
	res, err = privateCache.authorize(trustusername, check)
	if err != nil {
		t.Error(err)
	}
	if !res {
		t.Error("Wrong authorization result, authorization should pass.")
	}

	// deny delegated user access because assume role for this member doesn't exist in trust domain
	res, err = privateCache.authorize("invaliduser", check)
	if err != nil {
		t.Error(err)
	}
	if res {
		t.Error("Wrong authorization result, authorization should not pass.")
	}

	// deny access
	check = AthenzAccessCheck{
		Action:   "get",
		Resource: "home.domain:pods",
	}
	res, err = privateCache.authorize("fakeclient", check)
	if err != nil {
		t.Error(err)
	}
	if res {
		t.Error("Wrong authorization result, fakeclient's request should be denied")
	}

	// test case: one policy has two assertions, first assertion with explicitly Allow,
	// second assertion with explicitly Deny.
	check = AthenzAccessCheck{
		Action:   "delete",
		Resource: "home.domain.deny:services",
	}
	res, err = privateCache.authorize(username, check)
	if err != nil {
		t.Error(err)
	}
	if res {
		t.Error("Wrong authorization result, username's request should be denied since assertion has an explicit DENY")
	}

	check = AthenzAccessCheck{
		Action:   "create",
		Resource: "home.domain.deny:services",
	}
	res, err = privateCache.authorize(username, check)
	if err != nil {
		t.Error(err)
	}
	if !res {
		t.Error("Wrong authorization result, username's request should be allowed")
	}

	check = AthenzAccessCheck{
		Action:   "delete",
		Resource: "domain.does.not.exist:services",
	}
	res, err = privateCache.authorize(username, check)
	if err == nil {
		t.Error("there should be error because such domain doesn't exist in the cache")
	} else {
		assert.Equal(t, err.Error(), "domain.does.not.exist does not exist in cache map")
	}

	check = AthenzAccessCheck{
		Action:   "delete",
		Resource: "domain.wrong.format.services",
	}
	res, err = privateCache.authorize(username, check)
	if err == nil {
		t.Error("there should be error because resource string is invalid")
	} else {
		assert.Equal(t, err.Error(), "Error splitting domain name")
	}

	// check resource does not exist in cache
	check = AthenzAccessCheck{
		Action:   "get",
		Resource: "home.domain.test:pods",
	}
	res, err = privateCache.authorize(username, check)
	if err.Error() != "home.domain.test does not exist in cache map" {
		t.Error("should throw an error when domain does not exist in map")
	}

	// expired membership
	check = AthenzAccessCheck{
		Action:   "get",
		Resource: "home.domain.deny:pods",
	}
	item.Spec.Domain.Roles = []*zms.Role{
		{
			Members: []zms.MemberName{zms.MemberName(username)},
			Name:    zms.ResourceName(domainWithDeny + ":role.admin"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName(username + "1"),
					Expiration: &rdl.Timestamp{
						Time: time.Now().Add(time.Duration(-10) * time.Hour),
					},
				},
			},
		},
	}
	privateCache.addOrUpdateObj(item)
	res, err = privateCache.authorize(username+"1", check)
	if err != nil {
		t.Error(err)
	}
	if res {
		t.Error("Wrong authorization result. Membership has expired")
	}

	// disabled role principal
	systemDisabled := int32(1)
	check = AthenzAccessCheck{
		Action:   "get",
		Resource: "home.domain.deny:pods",
	}
	item.Spec.SignedDomain.Domain.Roles = []*zms.Role{
		{
			Members: []zms.MemberName{zms.MemberName(username + "2")},
			Name:    zms.ResourceName(domainWithDeny + ":role.admin"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName(username + "2"),
					Expiration: &rdl.Timestamp{
						Time: time.Now().Add(time.Duration(6) * time.Hour),
					},
					SystemDisabled: &systemDisabled,
				},
			},
		},
	}
	privateCache.addOrUpdateObj(item)
	res, err = privateCache.authorize(username+"2", check)
	if err != nil {
		t.Error(err)
	}
	if res {
		t.Error("Wrong authorization result. Member has been disabled by system.")
	}
}

func TestCheckUpdateTime(t *testing.T) {
	privateCache := newCache()
	privateCache.maxContactTime = 2 * time.Hour
	// wrong cm input, should give error
	err := privateCache.parseUpdateTime(cm0)
	if err == nil {
		t.Error("parseUpdateTime function should return error")
	} else {
		assert.Equal(t, err.Error(), "timestamp format in syncer config map is wrong")
	}

	// check if last update time is less than 2 hrs
	err = privateCache.parseUpdateTime(cm)
	if err != nil {
		t.Error("parseUpdateTime function should not return error")
	}
	assert.Equal(t, privateCache.cacheStatus, true)

	// check if last update is more than 2 hrs
	err = privateCache.parseUpdateTime(cm1)
	if err != nil {
		t.Error("parseUpdateTime function should not return error")
	}
	assert.Equal(t, privateCache.cacheStatus, false)
}
