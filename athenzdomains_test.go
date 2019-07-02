package webhook

import (
	"testing"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
	v1 "github.com/yahoo/k8s-athenz-istio-auth/pkg/apis/athenz/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	domainName = "home.domain"
	username   = "user.name"
)

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
									Resource: domainName + ".test:*",
									Action:   "*",
									Effect:   &allow,
								},
							},
							Modified: &timestamp,
							Name:     zms.ResourceName(domainName + ":policy.admin"),
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
			},
			Services: []*zms.ServiceIdentity{},
			Entities: []*zms.Entity{},
		},
		KeyId:     "colo-env-1.1",
		Signature: "signature",
	}
}

func newCache() *Cache {
	domainMap := make(map[string]CRMap)
	return &Cache{
		DomainMap: domainMap,
	}
}

func TestParseData(t *testing.T) {
	c := newCache()
	domainName := "home.domain"
	roleToPrincipals := make(map[string][]*zms.RoleMember)
	roleToAssertion := make(map[string][]SimpleAssertion)
	crMap := CRMap{
		RoleToPrincipals: roleToPrincipals,
		RoleToAssertion:  roleToAssertion,
	}
	c.DomainMap[domainName] = crMap
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeDomain(),
	}
	item := &v1.AthenzDomain{
		Spec: spec,
	}
	parseData(c.DomainMap, domainName, item)
	crMap, ok := c.DomainMap[domainName]
	if !ok {
		t.Error("Failed to add domain data to map")
	}
	if len(crMap.RoleToPrincipals) != 1 || crMap.RoleToPrincipals["home.domain:role.admin"] == nil {
		t.Error("Failed to create RoleToPrincipals map")
	}

	if len(crMap.RoleToAssertion) != 1 || crMap.RoleToPrincipals["home.domain:role.admin"] == nil {
		t.Error("Failed to create RoleToAssertion map")
	}
}

func TestAddObj(t *testing.T) {
	c := newCache()
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeDomain(),
	}
	item := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainName,
		},
		Spec: spec,
	}
	c.addObj(c.DomainMap, item)
	obj, ok := c.DomainMap[domainName]
	if !ok {
		t.Error("Failed to add AthenzDomain to domainMap")
	}
	if len(obj.RoleToPrincipals["home.domain:role.admin"]) != 1 {
		t.Error("Failed to add AthenzDomain to domainMap. RoleToPrincipals is empty.")
	}
}

func TestUpdateObj(t *testing.T) {
	timestamp, _ := rdl.TimestampParse("2019-06-21T19:28:09.305Z")
	c := newCache()
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeDomain(),
	}
	item := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainName,
		},
		Spec: spec,
	}
	c.addObj(c.DomainMap, item)
	_, ok := c.DomainMap[domainName]
	if !ok {
		t.Error("Failed to create AthenzDomain to domainMap")
	}
	item.Spec.Domain.Roles = []*zms.Role{
		{
			Members:  []zms.MemberName{zms.MemberName(username)},
			Modified: &timestamp,
			Name:     zms.ResourceName(domainName + ":role.admin.test1"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName(username),
				},
			},
		},
		{
			Members:  []zms.MemberName{zms.MemberName(username + "1")},
			Modified: &timestamp,
			Name:     zms.ResourceName(domainName + ":role.admin.test2"),
			RoleMembers: []*zms.RoleMember{
				{
					MemberName: zms.MemberName(username),
				},
			},
		},
	}
	c.updateObj(c.DomainMap, item)
	crMap, ok := c.DomainMap[domainName]
	if !ok {
		t.Error("Failed to keep AthenzDomain to domainMap")
	}
	if len(crMap.RoleToPrincipals) != 2 {
		t.Error(len(crMap.RoleToPrincipals))
		t.Error("Failed to update AthenzDomain roles")
	}
}

func TestDeleteObj(t *testing.T) {
	c := newCache()
	spec := v1.AthenzDomainSpec{
		SignedDomain: getFakeDomain(),
	}
	item := &v1.AthenzDomain{
		ObjectMeta: metav1.ObjectMeta{
			Name: domainName,
		},
		Spec: spec,
	}
	c.addObj(c.DomainMap, item)
	_, ok := c.DomainMap[domainName]
	if !ok {
		t.Error("Failed to add AthenzDomain to domainMap")
	}
	c.deleteObj(c.DomainMap, item)
	_, ok = c.DomainMap[domainName]
	if ok {
		t.Error("Failed to delete AthenzDomain to domainMap")
	}
}
