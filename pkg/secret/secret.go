package secret

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync-secrets/pkg/helper"

	log "github.com/sirupsen/logrus"
)

var (
	DevEnv     = Environment{Name: "dev", Production: false, IsGroup: false}
	TestEnv    = Environment{Name: "test", Production: false, IsGroup: false}
	StagingEnv = Environment{Name: "staging", Production: false, IsGroup: false}
	ProdEnv    = Environment{Name: "prod", Production: true, IsGroup: false}
	NonprodEnv = Environment{Name: "nonprod", Production: false, IsGroup: true}
	GlobalEnv  = Environment{Name: "global", Production: true, IsGroup: true}
)

type Environment struct {
	Name       string
	Production bool // true = environment is prod or a group including prod
	IsGroup    bool // true = environment is a group for multiple envs
}

// A secret containing name/path, map of data, and map of tags/metadata.
type Secret struct {
	Name        string
	Data        map[string]interface{}
	Environment *Environment
	Tags        map[string]interface{}
}

// New creates and returns a Secret with Data and Tags initialized.
func New(name string) *Secret {
	secret := Secret{
		Name: name,
		Data: make(map[string]interface{}),
		Tags: make(map[string]interface{}),
	}

	return &secret
}

// AddData appends given data to secret's Data.
func (s *Secret) AddData(data map[string]interface{}) {
	for key, value := range data {
		s.Data[key] = value
	}
}

// AddTags appends given tags to secret's Tags.
func (s *Secret) AddTags(tags map[string]interface{}) {
	for key, value := range tags {
		s.Tags[key] = value
	}
}

// BelongsToEnv returns a boolean indicating whether s.Environment "belongs" to env.
func (s *Secret) BelongsToEnv(env *Environment) bool {
	if env == nil || s.Environment == nil {
		return false
	}

	secretEnv := *s.Environment
	systemEnv := *env

	if secretEnv == systemEnv {
		return true
	}

	if secretEnv == GlobalEnv || systemEnv == GlobalEnv {
		return true
	}

	if (!secretEnv.Production && systemEnv == NonprodEnv) ||
		(secretEnv == NonprodEnv && !systemEnv.Production) {
		return true
	}

	return false
}

// ContainsTag returns a boolean indicating whether s.Tags contain a tag with key.
func (s *Secret) ContainsTag(key string) bool {
	return s.Tags[key] != nil
}

// ContainsTag checks whether s contaings a Tag with key and value.
func (s *Secret) ContainsTagWithValue(key string, val interface{}) bool {
	if s.Tags[key] == val {
		return true
	} else {
		return false
	}
}

// Equal returns a boolean indicating whether s is fully equal to o.
func (s *Secret) Equal(o *Secret) bool {
	return s.EqualName(o) && s.EqualData(o) && s.EqualTags(o)
}

// EqualData returns a boolean indicating whether s.Data is equal to o.Data.
func (s *Secret) EqualData(o *Secret) bool {
	return helper.DeepEqual(s.Data, o.Data)
}

// EqualName returns a boolean indicating whether s.Name is equal to o.Name.
func (s *Secret) EqualName(o *Secret) bool {
	return s.Name == o.Name
}

// EqualTags returns a boolean indicating whether s.Tags is equal to o.Tags.
func (s *Secret) EqualTags(o *Secret) bool {
	return helper.DeepEqual(s.Tags, o.Tags)
}

// GetEnv returns the environment from s.Environment, s.Name, and from s.Tags, in that order.
func (s *Secret) GetEnv() *Environment {
	// If s.Environment is set, return that
	if s.Environment != nil {
		return s.Environment
	}

	// Alteranitively, check env from name
	if env := s.GetEnvFromName(); env != nil {
		return env
	}

	// Finally, check env from s.Tags (or an empty Environment)
	if env := s.GetEnvFromTags(); env != nil {
		return env
	}

	return nil
}

// GetEnvFromName returns an Environment if one is defined in s.Name as suffix separated by dash.
func (s *Secret) GetEnvFromName() *Environment {
	var env string
	nameSplit := strings.Split(s.Name, "-")
	if len(nameSplit) > 1 {
		env = nameSplit[len(nameSplit)-1]
	}
	return GetEnvFromString(env)
}

// GetEnvFromTags returns an Environment if one is defined in s.Tags.
func (s *Secret) GetEnvFromTags() *Environment {
	env := s.GetTagValue("Environment")
	return GetEnvFromString(env)
}

// GetTagValue returns the value of s.Tag with key.
func (s *Secret) GetTagValue(key string) string {
	var val string

	if s.ContainsTag(key) {
		val = fmt.Sprintf("%v", s.Tags[key])
	}

	return val
}

// SetEnv retrieves the name of the environment and inserts it into s.Environment.
func (s *Secret) SetEnv() {
	s.Environment = s.GetEnv()
}

// TrimNameEnv removes any Environment.Name from s.Name. (For example, "dev/platform/my-secret-dev"
// would be modified to "dev/platform/my-secret").
func (s *Secret) TrimNameEnv() {
	if env := s.GetEnvFromName(); env != nil {
		s.TrimNameSuffix("-" + env.Name)
	}
}

// TrimNamePath removes any path from name, leaving just anything after last slash. For example,
// the name "dev/platform/secret/my-secret" would be updated to "my-secret".
func (s *Secret) TrimNamePath() {
	if len(s.Name) > 0 {
		n := strings.Split(s.Name, "/")
		s.Name = n[len(n)-1]
	}
}

// TrimNameSuffix removes the given suffix from secret's Name.
func (s *Secret) TrimNameSuffix(suffix string) {
	s.Name = strings.TrimSuffix(s.Name, suffix)
}

// GetEnvFromString translates env to an Environment by comparing its names.
func GetEnvFromString(env string) *Environment {
	switch env {
	case DevEnv.Name:
		return &DevEnv
	case TestEnv.Name:
		return &TestEnv
	case StagingEnv.Name:
		return &StagingEnv
	case ProdEnv.Name:
		return &ProdEnv
	case GlobalEnv.Name:
		return &GlobalEnv
	case NonprodEnv.Name:
		return &NonprodEnv
	default:
		return nil
	}
}

// FilterByTags returns a sublist of secrets which does not contain any tags listed by GetFilterTags.
func FilterByTags(secrets []Secret, tags map[string]interface{}) (bool, []Secret) {
	if len(tags) > 0 {
		tagsJson, _ := json.Marshal(tags)
		log.Infof("Filtering secrets with tags %v", string(tagsJson))

		var filteredSecrets []Secret
		var containsTag bool
		for _, secret := range secrets {
			containsTag = true
			for key, val := range tags {
				if !secret.ContainsTagWithValue(key, val) {
					containsTag = false
				}
			}

			if containsTag {
				filteredSecrets = append(filteredSecrets, secret)
			}
		}
		return true, filteredSecrets
	} else {
		return false, secrets
	}
}

// ParseFilterTags returns the tagsString (format "TAG1=VALUE1;TAG2=VALUE2") parsed into a map.
func ParseFilterTags(tagsString string) map[string]interface{} {
	tags := make(map[string]interface{})

	if len(tagsString) > 0 {
		for _, tag := range strings.Split(tagsString, ";") {
			kvs := strings.Split(tag, "=")
			if len(kvs) != 2 {
				log.Panicf("Cannot parse tag filter '%s'", tag)
			}

			tags[kvs[0]] = kvs[1]
		}
	}

	return tags
}
