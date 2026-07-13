package spicedb

import (
	_ "embed"
	"fmt"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

func calculateConsistency(zedToken string) *v1.Consistency {
	if zedToken != "" {
		return &v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: &v1.ZedToken{Token: zedToken}}}
	}
	return &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}
}

// ParseResource splits a resource string of the form "<object_type>:<object_id>"
func ParseResource(resource string) (ObjectType, string, error) {
	parts := strings.SplitN(resource, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid resource format: %s", resource)
	}
	// normalize organization to org as that's what we use internally
	if parts[0] == "organization" {
		parts[0] = "org"
	}
	return ObjectType(parts[0]), parts[1], nil
}

// BuildRelation constructs a SpiceDB relationship object.
func BuildRelation(relation Relation, objectType ObjectType, objectId string, subjectType ObjectType, subjectId string) *v1.Relationship {
	return &v1.Relationship{
		Resource: &v1.ObjectReference{
			ObjectType: objectType.String(),
			ObjectId:   objectId,
		},
		Relation: relation.String(),
		Subject: &v1.SubjectReference{
			Object: &v1.ObjectReference{
				ObjectType: string(subjectType),
				ObjectId:   subjectId,
			},
		},
	}
}
