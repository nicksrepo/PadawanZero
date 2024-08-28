package state

import (
	"fmt"
	"math"

	"gonum.org/v1/gonum/mat"
)

type Matrix struct {
	Data *mat.Dense
}

type IState interface {
	Copy() *Matrix
	Apply(state interface{}, callbackFunc func(data interface{}) error)
	IsValid() bool
	Randomize(probability float32)
	PrintASCII()
}

func (sm *Matrix) Copy() *Matrix {
	sm.PrintASCII()
	return &Matrix{
		Data: mat.DenseCopyOf(sm.Data),
	}
}

type ObjectState struct {
	from  int
	to    int
	value float64
	data  Matrix
}

func (sm *Matrix) Apply(objs ...ObjectState) {
	if len(objs) > 1 {
		for _, obj := range objs {
			sm.Data.Set(obj.from, 0, obj.data.Data.At(int(obj.value), 0))
			sm.Data.Set(obj.to, 0, obj.data.Data.At(int(obj.value), 0))
		}
	}
}

func (sm *Matrix) PrintASCII() {
	rows, cols := sm.Data.Dims()
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			value := sm.Data.At(i, j)
			if math.IsNaN(value) {
				fmt.Print("  X  ")
			} else {
				fmt.Printf("%5.2f", value)
			}
		}
		fmt.Println()
	}
}
