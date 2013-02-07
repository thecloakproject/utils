// Steve Phillips / elimisteve
// 2013.02.07

package utils

import (
	"fmt"
)

func SumEmptyInterfaceSlice(params []interface{}) (float64, error) {
	var sum float64 = 0.0
	var err error

	// Parse params as a slice of float64s to add
	for _, n := range params {
		num, ok := n.(float64)
		if ok {
			sum += num
			continue
		}
		sum = 0
		err = fmt.Errorf("Couldn't parse params '%+v' as float64s", params)
		break
	}
	return sum, err
}
