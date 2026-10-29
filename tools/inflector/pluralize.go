package inflector

import (
	"log"
	"regexp"
)

// note: the patterns are the inverse of the singularRules
var pluralRules = []struct {
	pattern     string // lazily compiled
	replacement string
}{
	{"(?i)([nrlm]ese|deer|fish|sheep|measles|ois|pox|media|news|series)$", "${1}"},
	{"(?i)^(sea[- ]bass)$", "${1}"},
	{"(?i)(s)tatus$", "${1}tatuses"},
	{"(?i)(f)oot$", "${1}eet"},
	{"(?i)(t)ooth$", "${1}eeth"},
	{"(?i)(quiz)$", "${1}zes"},
	{"(?i)(matr)ix$", "${1}ices"},
	{"(?i)(vert|ind)ex$", "${1}ices"},
	{"(?i)^(ox)$", "${1}en"},
	{"(?i)(alias)$", "${1}es"},
	{"(?i)(alumn|bacill|cact|foc|fung|nucle|radi|stimul|syllab|termin)us$", "${1}i"},
	{"(?i)([ftw]ax)$", "${1}es"},
	{"(?i)(cris|ax|test)is$", "${1}es"},
	{"(?i)(buffal|her|potat|tomat|ech)o$", "${1}oes"},
	{"(?i)([ml])ouse$", "${1}ice"},
	{"(?i)(x|ch|ss|sh|us)$", "${1}es"},
	{"(?i)([^aeiouy]|qu)y$", "${1}ies"},
	{"(?i)(hive|tive|drive)$", "${1}s"},
	{"(?i)([lr])f$", "${1}ves"},
	{"(?i)([^f])fe$", "${1}ves"},
	{"(?i)sis$", "ses"},
	{"(?i)([ti])um$", "${1}a"},
	{"(?i)(p)erson$", "${1}eople"},
	{"(?i)^((?:wo)?m)an$", "${1}en"},
	{"(?i)(c)hild$", "${1}hildren"},
	{"(?i)eau$", "eaus"},
	{"(?i)$", "s"},
}

// Pluralize converts the specified word into its plural version.
//
// For example:
//
//	inflector.Pluralize("person") // "people"
func Pluralize(word string) string {
	if word == "" {
		return ""
	}

	for _, rule := range pluralRules {
		re := compiledPatterns.GetOrSet(rule.pattern, func() *regexp.Regexp {
			re, err := regexp.Compile(rule.pattern)
			if err != nil {
				return nil
			}
			return re
		})
		if re == nil {
			// log only for debug purposes
			log.Println("[Pluralize] failed to retrieve/compile rule pattern " + rule.pattern)
			continue
		}

		if re.MatchString(word) {
			return re.ReplaceAllString(word, rule.replacement)
		}
	}

	return word
}
