package common

import "encoding/json"

var GroupRatio = map[string]float64{
	LinuxDoTrustLevel0: 1,
	LinuxDoTrustLevel1: 1,
	LinuxDoTrustLevel2: 1,
	LinuxDoTrustLevel3: 1,
	LinuxDoTrustLevel4: 1,
}

func GroupRatio2JSONString() string {
	jsonBytes, err := json.Marshal(GroupRatio)
	if err != nil {
		SysError("error marshalling model ratio: " + err.Error())
	}
	return string(jsonBytes)
}

func UpdateGroupRatioByJSONString(jsonStr string) error {
	GroupRatio = make(map[string]float64)
	return json.Unmarshal([]byte(jsonStr), &GroupRatio)
}

func GetGroupRatio(name string) float64 {
	ratio, ok := GroupRatio[name]
	if !ok {
		SysError("group ratio not found: " + name)
		return 1
	}
	return ratio
}
