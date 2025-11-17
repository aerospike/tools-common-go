package flags

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type UtilsTestSuite struct {
	suite.Suite
}

func (s *UtilsTestSuite) TestWrapString() {
	testCases := []struct {
		input    string
		lineLen  int
		expected string
	}{
		{
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			lineLen:  20,
			expected: "Lorem ipsum dolor \nsit amet, consectetur \nadipiscing elit.",
		},
		{
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			lineLen:  30,
			expected: "Lorem ipsum dolor sit amet, \nconsectetur adipiscing elit.",
		},
		{
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			lineLen:  50,
			expected: "Lorem ipsum dolor sit amet, consectetur adipiscing \nelit.",
		},
		{
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			lineLen:  80,
			expected: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		},
		{
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			lineLen:  100,
			expected: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		},
	}

	for _, tc := range testCases {
		s.T().Run("", func(_ *testing.T) {
			actual := WrapString(tc.input, tc.lineLen)
			s.Equal(tc.expected, actual)
		})
	}
}

func (s *UtilsTestSuite) TestDefaultWrapHelpString() {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
			expected: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		},
		{
			input: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed ut perspiciatis unde omnis iste " +
				"natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam.",
			expected: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed ut \n" +
				"perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque \n" +
				"laudantium, totam rem aperiam.",
		},
		{
			input: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed ut perspiciatis unde omnis iste " +
				"natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam. Eaque ipsa " +
				"quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.",
			expected: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed ut \n" +
				"perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque \n" +
				"laudantium, totam rem aperiam. Eaque ipsa quae ab illo inventore veritatis et \n" +
				"quasi architecto beatae vitae dicta sunt explicabo.",
		},
	}

	for _, tc := range testCases {
		s.T().Run("", func(_ *testing.T) {
			actual := DefaultWrapHelpString(tc.input)
			s.Equal(tc.expected, actual)
		})
	}
}

func TestUtilsTestSuite(t *testing.T) {
	suite.Run(t, new(UtilsTestSuite))
}
