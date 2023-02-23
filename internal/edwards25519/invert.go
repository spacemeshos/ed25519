// Copyright 2019 Spacemesh Authors
// edwards25519 invert mod l

package edwards25519

// InvertModL computes z mod l and puts the result into out
func InvertModL(out, z *Scalar) {

	var t0, t1, t2, t3, t4, t5, tz Scalar

	t1.SetCanonicalBytes(z.Bytes()) // 2^0
	squareModL(&t0, z)              // 2^1
	multModL(&t2, &t0, z)           // 2^1 + 2^0
	for i := 1; i < 2; i++ {        // 2^2
		squareModL(&t0, &t0)
	}
	multModL(&t3, &t0, &t2)  // 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^3
		squareModL(&t0, &t0)
	}
	multModL(&t4, &t0, &t3)  // 2^3 + 2^2 + 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^4
		squareModL(&t0, &t0)
	}
	multModL(&t5, &t0, &t4) // 2^4 + 2^3 + 2^2 + 2^1 + 2^0

	tz.SetCanonicalBytes(t1.Bytes()) // 2^252
	for i := 1; i < 129; i++ {       // 2^128
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // tz = 252, 124
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // 2^124 + 2^122
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // 2^124 + 2^122 + 2^119 + 2^118
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // 124,122,119,118,116..113
	for i := 1; i < 7; i++ { // 2^6
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t5)  // 124,122,119,118,116..113, 111..107
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // 124,122,119,118,116..113, 111..107, 104..102
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, 100..97
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95, 93
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95, 93, 89
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, 100..97, 95,93,89,87..84
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62,60,59
	for i := 1; i < 8; i++ { // 2^7
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, 100..97, 95,93,89,87..84, 82..79, 76..74 ,71,70,68,66,65,62,60,59,52
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, **100.....52**, 49,46,45
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, **100.....52**, 49,46,45,41,40
	for i := 1; i < 6; i++ { // 2^5
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t2)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26
	for i := 1; i < 7; i++ { // 2^6
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t4)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18
	for i := 1; i < 5; i++ { // 2^4
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t3)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12
	for i := 1; i < 8; i++ { // 2^7
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t5)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5
	for i := 1; i < 3; i++ { // 2^2
		squareModL(&tz, &tz)
	}
	multModL(&tz, &tz, &t1)  // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&tz, &tz)
	}
	tz.Multiply(&tz, &t2) // **124.....102**, **100.....52**, 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0

	out.Set(&tz)
}

func squareModL(out, z *Scalar) {
	out.Multiply(z, z)
}

func multModL(out, z, w *Scalar) {
	out.Multiply(z, w)
}
