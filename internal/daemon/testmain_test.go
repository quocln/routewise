package daemon

import (
	"os"
	"testing"

	"github.com/quocln/routewise/internal/testenv"
)

func TestMain(m *testing.M) { os.Exit(testenv.RunProtected(m)) }
