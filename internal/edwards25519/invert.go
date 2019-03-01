// Copyright 2019 Spacemesh Authors
// edwards25519 invert mod l

package edwards25519

func InvertModL(out, z *[32]byte) {

	// This function is not optimized

	var t0, t1, t2, t3, t4, t5, tz, zero [32]byte

	copy(t1[:], z[:])        // 2^0
	squareModL(&t0, z)       // 2^1
	multModL(&t2, &t0, z)    // 2^1 + 2^0
	for i := 1; i < 2; i++ { // 2^2
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

	copy(tz[:], t2[:]) // tz = 2^1 + 2^0

	copy(t0[:], t1[:])
	for i := 1; i < 4; i++ { // 2^3
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 2^3 + 2^1 + 2^0
	copy(t0[:], t5[:])
	for i := 1; i < 6; i++ { // 2^9 + 2^8 + 2^7 + 2^6 + 2^5
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 2^9 + 2^8 + 2^7 + 2^6 + 2^5 + 2^3 + 2^1 + 2^0
	copy(t0[:], t1[:])
	for i := 1; i < 13; i++ { // 2^12
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 2^12 + 2^9 + 2^8 + 2^7 + 2^6 + 2^5 + 2^3 + 2^1 + 2^0
	copy(t0[:], t3[:])
	for i := 1; i < 15; i++ { // 2^16 + 2^15 + 2^14
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 19; i++ { // 2^18
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t4[:])
	for i := 1; i < 21; i++ { // 2^23 + 2^22 + 2^21 + 2^20
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t3[:])
	for i := 1; i < 27; i++ { // 2^28 + 2^27 + 2^26
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 31; i++ { // 2^30
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 34; i++ { // 2^33
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 36; i++ { // 2^36 + 2^35
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 41; i++ { // 2^41 + 2^40
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t2[:])
	for i := 1; i < 46; i++ { // 2^46 + 2^45
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 50; i++ { // 2^49
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 49,46,45,41,40,36,35,33,30,28..26, 23..20, 18,16..14, 12,9..5, 3,1,0
	copy(t0[:], t1[:])
	for i := 1; i < 53; i++ { // 2^52
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 60; i++ { // 2^60 + 2^59
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 63; i++ { // 2^62
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 62,60,59,52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 66; i++ { // 2^66 + 2^65
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 69; i++ { // 2^68
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 71; i++ { // 2^71 + 2^70
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 75; i++ { // 2^76 + 2^75 + 2^74
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 80; i++ { // 2^82 + 2^81 + 2^80 + 2^79
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 85; i++ { // 2^87 + 2^86 + 2^85 + 2^84
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 90; i++ { // 2^89
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 94; i++ { // 2^93
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 96; i++ { // 2^95
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 95,93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 98; i++ { // 2^100 + 2^99 + 2^98 + 2^97
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 100..97, 95,93,89,87..84, 82..79, 75..74, 71,70,68,66,65,62,60,59,52, **49.....0**
	copy(t0[:], t3[:])
	for i := 1; i < 103; i++ { // 2^104 + 2^103 + 2^102
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 104..102, **100.....52**, **49.....0**
	copy(t0[:], t5[:])
	for i := 1; i < 108; i++ { // 2^111 + 2^110 + 2^109 + 2^108 + 2^107
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t4[:])
	for i := 1; i < 114; i++ { // 2^116 + 2^115 + 2^114 + 2^113
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t2[:])
	for i := 1; i < 119; i++ { // 2^119 + 2^118
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 123; i++ { // 2^122
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 122,119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], t1[:])
	for i := 1; i < 125; i++ { // 2^124
		squareModL(&t0, &t0)
	}
	multModL(&tz, &t0, &tz) // tz = 124,122,119,118,116..113, 111..107, 104..102, **100.....52**, **49.....0**
	copy(t0[:], z[:])
	for i := 1; i < 253; i++ { // 2^252
		ScMulAdd(&t0, &t0, &t0, &zero)
	}
	multModL(&tz, &t0, &tz) // tz = 252, 124......

	copy(out[:], tz[:])
}

func squareModL(out, z *[32]byte) {
	var zero [32]byte
	ScMulAdd(out, z, z, &zero)
}

func multModL(out, z *[32]byte, w *[32]byte) {
	var zero [32]byte
	ScMulAdd(out, z, w, &zero)
}
