// Copyright 2019 Spacemesh Authors
// edwards25519 invert mod l

package edwards25519

// InvertModL computes 1/x mod l and puts the result into s
func (s *Scalar) InvertModL(x *Scalar) *Scalar {

	t1 := NewScalar().Set(x)          // 2^0
	t0 := NewScalar().Multiply(x, x)  // 2^1
	t2 := NewScalar().Multiply(t0, x) // 2^1 + 2^0
	for i := 1; i < 2; i++ {          // 2^2
		t0.Multiply(t0, t0)
	}
	t3 := NewScalar().Multiply(t0, t2) // 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ {           // 2^3
		t0.Multiply(t0, t0)
	}
	t4 := NewScalar().Multiply(t0, t3) // 2^3 + 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ {           // 2^4
		t0.Multiply(t0, t0)
	}
	t5 := NewScalar().Multiply(t0, t4) // 2^4 + 2^3 + 2^2 + 2^1 + 2^0

	tz := NewScalar().Set(x)   // 2^252
	for i := 1; i < 129; i++ { // 2^128
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // tz = 252, 124
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // 2^124 + 2^122
	for i := 1; i < 5; i++ { // 2^4
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2)      // 2^124 + 2^122 + 2^119 + 2^118
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t4)      // 124,122,119,118,116..113
	for i := 1; i < 7; i++ { // 2^6
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t5)      // 124,122,119,118,116..113, 111..107
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t3)      // 124,122,119,118,116..113, 111..107, 104..102
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t4)      // **124.....102**, 100..97
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, 100..97, 95
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, 100..97, 95, 93
	for i := 1; i < 5; i++ { // 2^4
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, 100..97, 95, 93, 89
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t4)      // **124.....102**, 100..97, 95,93,89,87..84
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t4)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t3)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74
	for i := 1; i < 5; i++ { // 2^4
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68
	for i := 1; i < 4; i++ { // 2^3
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65
	for i := 1; i < 4; i++ { // 2^3
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62
	for i := 1; i < 4; i++ { // 2^3
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62,60,59
	for i := 1; i < 8; i++ { // 2^7
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62,60,59,52
	for i := 1; i < 4; i++ { // 2^3
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, **100.....52**, 49
	for i := 1; i < 5; i++ { // 2^4
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2)      // **124.....102**, **100.....52**, 49,46,45
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2)      // **124.....102**, **100.....52**, 49,46,45,41,40
	for i := 1; i < 6; i++ { // 2^5
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33
	for i := 1; i < 4; i++ { // 2^3
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30
	for i := 1; i < 5; i++ { // 2^4
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t3)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26
	for i := 1; i < 7; i++ { // 2^6
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t4)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18
	for i := 1; i < 5; i++ { // 2^4
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t3)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12
	for i := 1; i < 8; i++ { // 2^7
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t5)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5
	for i := 1; i < 3; i++ { // 2^2
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t1)      // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3
	for i := 1; i < 4; i++ { // 2^3
		tz.Multiply(tz, tz)
	}
	tz.Multiply(tz, t2) // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0

	s.Set(tz)
	return s
}
