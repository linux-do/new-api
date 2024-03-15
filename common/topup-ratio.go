package common

import "encoding/json"

var TopupGroupRatio = map[string]float64{
	LinuxDoTrustLevel0: 1,
	LinuxDoTrustLevel1: 1,
	LinuxDoTrustLevel2: 1,
	LinuxDoTrustLevel3: 1,
	LinuxDoTrustLevel4: 1,
}

func TopupGroupRatio2JSONString() string {
	jsonBytes, err := json.Marshal(TopupGroupRatio)
	if err != nil {
		SysError("error marshalling model ratio: " + err.Error())
	}
	return string(jsonBytes)
}

func UpdateTopupGroupRatioByJSONString(jsonStr string) error {
	TopupGroupRatio = make(map[string]float64)
	return json.Unmarshal([]byte(jsonStr), &TopupGroupRatio)
}

func GetTopupGroupRatio(name string) float64 {
	ratio, ok := TopupGroupRatio[name]
	if !ok {
		SysError("topup group ratio not found: " + name)
		return 1
	}
	return ratio
}
