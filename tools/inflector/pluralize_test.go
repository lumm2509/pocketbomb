package inflector_test

import (
	"testing"

	"github.com/lumm2509/pocketbomb/tools/inflector"
)

func TestPluralize(t *testing.T) {
	scenarios := []struct {
		word     string
		expected string
	}{
		{"", ""},
		{"abcnese", "abcnese"},
		{"deer", "deer"},
		{"sheep", "sheep"},
		{"measles", "measles"},
		{"pox", "pox"},
		{"media", "media"},
		{"sea-bass", "sea-bass"},
		{"Status", "Statuses"},
		{"Foot", "Feet"},
		{"Tooth", "Teeth"},
		{"abcmenu", "abcmenus"},
		{"Quiz", "Quizzes"},
		{"Matrix", "Matrices"},
		{"Vertex", "Vertices"},
		{"Index", "Indices"},
		{"Alias", "Aliases"},
		{"Alumnus", "Alumni"},
		{"Bacillus", "Bacilli"},
		{"Cactus", "Cacti"},
		{"Fungus", "Fungi"},
		{"Nucleus", "Nuclei"},
		{"Radius", "Radii"},
		{"Stimulus", "Stimuli"},
		{"Syllabus", "Syllabi"},
		{"Terminus", "Termini"},
		{"Virus", "Viruses"},
		{"Fax", "Faxes"},
		{"Crisis", "Crises"},
		{"Axis", "Axes"},
		{"Ox", "Oxen"},
		{"Fox", "Foxes"},
		{"Shoe", "Shoes"},
		{"Tomato", "Tomatoes"},
		{"Photo", "Photos"},
		{"House", "Houses"},
		{"Mouse", "Mice"},
		{"abcx", "abcxes"},
		{"Bus", "Buses"},
		{"Church", "Churches"},
		{"Movie", "Movies"},
		{"Series", "Series"},
		{"abcquy", "abcquies"},
		{"Category", "Categories"},
		{"Day", "Days"},
		{"Relative", "Relatives"},
		{"Drive", "Drives"},
		{"aardwolf", "aardwolves"},
		{"Knife", "Knives"},
		{"Analysis", "Analyses"},
		{"Diagnosis", "Diagnoses"},
		{"Datum", "Data"},
		{"Album", "Albums"},
		{"Person", "People"},
		{"Man", "Men"},
		{"Woman", "Women"},
		{"Human", "Humans"},
		{"Child", "Children"},
		{"News", "News"},
		{"Tableau", "Tableaus"},
		{"Currency", "Currencies"},
		{"blog_post", "blog_posts"},
		{"abc", "abcs"},
	}

	for _, s := range scenarios {
		t.Run(s.word, func(t *testing.T) {
			result := inflector.Pluralize(s.word)
			if result != s.expected {
				t.Fatalf("Expected %q, got %q", s.expected, result)
			}
		})
	}
}

func TestPluralizeSingularizeRoundtrip(t *testing.T) {
	words := []string{
		"products", "categories", "blog_posts", "people", "children", "statuses", "boxes",
		"buses", "addresses", "knives", "analyses", "matrices", "mice", "quizzes", "orders",
	}

	for _, word := range words {
		t.Run(word, func(t *testing.T) {
			result := inflector.Pluralize(inflector.Singularize(word))
			if result != word {
				t.Fatalf("Expected %q, got %q", word, result)
			}
		})
	}
}
