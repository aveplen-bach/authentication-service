package util

import (
	"fmt"
	"strconv"
	"strings"
)

func SerializeFloats64(fs []float64) string {
	var res string
	for i := 0; i < len(fs)-1; i++ {
		res += fmt.Sprintf("%f;", fs[i])
	}
	res += fmt.Sprintf("%f", fs[len(fs)-1])
	return res
}

func DeserializeFloats64(s string) []float64 {
	var res []float64
	for _, frag := range strings.Split(s, ";") {
		f, _ := strconv.ParseFloat(frag, 64)
		res = append(res, f)
	}
	return res
}
