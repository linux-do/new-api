package common

import "fmt"

const (
	LinuxDoTrustLevel0 = "Level0"
	LinuxDoTrustLevel1 = "level1"
	LinuxDoTrustLevel2 = "level2"
	LinuxDoTrustLevel3 = "level3"
	LinuxDoTrustLevel4 = "level4"
)

type TrustLevel int

func (l TrustLevel) String() string {
	return fmt.Sprintf("level%d", l)
}
