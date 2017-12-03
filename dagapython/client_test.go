package dagapython

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateRequest(t *testing.T) {
	//Normal execution
	clients, servers, context, _ := generateTestContext(rand.Intn(10)+1, rand.Intn(10)+1)
	T0, S, s, err := clients[0].CreateRequest(context)
	if err != nil {
		assert.Equal(t, T0, nil, "T0 not nil on error")
		assert.Equal(t, S, nil, "S not nil on error")
		assert.Equal(t, s, nil, "s not nil on error")
		t.Error("Cannot create request under regular context")
	}

	if T0 == nil {
		t.Error("T0 empty")
	}
	if T0.Equal(suite.Point().Null()) {
		t.Error("T0 is the null point")
	}

	if S == nil {
		t.Error("S is empty")
	}
	if len(S) != len(servers)+2 {
		t.Errorf("S has the wrong length: %d instead of %d", len(S), len(servers)+2)
	}
	for i, temp := range S {
		if temp.Equal(suite.Point().Null()) {
			t.Errorf("Null point in S at position %d", i)
		}
	}

	if s == nil {
		t.Error("s is empty")
	}

}
