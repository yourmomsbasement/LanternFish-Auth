package gate

import "errors"

// A small QR code encoder (byte mode, error correction level M, versions
// 1-10), enough for enrollment links. It follows ISO/IEC 18004 and the
// structure of Project Nayuki's reference implementation.

type qrVersion struct {
	ecPerBlock     int
	blocks1, data1 int // group 1: blocks, data codewords each
	blocks2, data2 int // group 2
	align          []int
}

var qrVersionsM = [...]qrVersion{
	1:  {10, 1, 16, 0, 0, nil},
	2:  {16, 1, 28, 0, 0, []int{6, 18}},
	3:  {26, 1, 44, 0, 0, []int{6, 22}},
	4:  {18, 2, 32, 0, 0, []int{6, 26}},
	5:  {24, 2, 43, 0, 0, []int{6, 30}},
	6:  {16, 4, 27, 0, 0, []int{6, 34}},
	7:  {18, 4, 31, 0, 0, []int{6, 22, 38}},
	8:  {22, 2, 38, 2, 39, []int{6, 24, 42}},
	9:  {22, 3, 36, 2, 37, []int{6, 26, 46}},
	10: {26, 4, 43, 1, 44, []int{6, 28, 50}},
}

func (v qrVersion) dataCodewords() int { return v.blocks1*v.data1 + v.blocks2*v.data2 }

type qrCode struct {
	size     int
	dark     [][]bool
	function [][]bool
}

func (q *qrCode) set(x, y int, dark bool) {
	q.dark[y][x] = dark
	q.function[y][x] = true
}

// qrEncode returns the modules of a QR code for data, dark = true, with no
// quiet zone (draw four light modules around it).
func qrEncode(data []byte) ([][]bool, error) {
	ver := 0
	for v := 1; v < len(qrVersionsM); v++ {
		countBits := 8
		if v >= 10 {
			countBits = 16
		}
		if 4+countBits+8*len(data) <= 8*qrVersionsM[v].dataCodewords() {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("text too long for a QR code")
	}
	codewords := qrCodewords(data, ver)

	best, bestPenalty := (*qrCode)(nil), -1
	for mask := 0; mask < 8; mask++ {
		q := qrBase(ver)
		q.drawCodewords(codewords)
		q.applyMask(mask)
		q.drawFormat(mask)
		if p := q.penalty(); bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = q, p
		}
	}
	return best.dark, nil
}

// qrEncodeMask is qrEncode with a fixed mask, for tests.
func qrEncodeMask(data []byte, ver, mask int) [][]bool {
	q := qrBase(ver)
	q.drawCodewords(qrCodewords(data, ver))
	q.applyMask(mask)
	q.drawFormat(mask)
	return q.dark
}

func qrCodewords(data []byte, ver int) []byte {
	v := qrVersionsM[ver]
	countBits := 8
	if ver >= 10 {
		countBits = 16
	}
	var bits []bool
	put := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, val>>uint(i)&1 == 1)
		}
	}
	put(0b0100, 4)
	put(len(data), countBits)
	for _, b := range data {
		put(int(b), 8)
	}
	capacity := 8 * v.dataCodewords()
	for i := 0; i < 4 && len(bits) < capacity; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	for pad := 0xEC; len(bits) < capacity; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	dataCw := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			dataCw[i/8] |= 1 << uint(7-i%8)
		}
	}

	// Split into blocks, add error correction, interleave.
	gen := rsGenerator(v.ecPerBlock)
	var blocks, ecc [][]byte
	off := 0
	for i := 0; i < v.blocks1+v.blocks2; i++ {
		n := v.data1
		if i >= v.blocks1 {
			n = v.data2
		}
		blk := dataCw[off : off+n]
		off += n
		blocks = append(blocks, blk)
		ecc = append(ecc, rsRemainder(blk, gen))
	}
	var out []byte
	for i := 0; i < max(v.data1, v.data2); i++ {
		for _, blk := range blocks {
			if i < len(blk) {
				out = append(out, blk[i])
			}
		}
	}
	for i := 0; i < v.ecPerBlock; i++ {
		for _, e := range ecc {
			out = append(out, e[i])
		}
	}
	return out
}

// GF(256) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1.
func gfMul(x, y byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		hi := z >> 7
		z = z<<1 ^ hi*0x1D
		if y>>uint(i)&1 == 1 {
			z ^= x
		}
	}
	return z
}

func rsGenerator(degree int) []byte {
	res := make([]byte, degree)
	res[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := range res {
			res[j] = gfMul(res[j], root)
			if j+1 < len(res) {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return res
}

func rsRemainder(data, gen []byte) []byte {
	res := make([]byte, len(gen))
	for _, b := range data {
		factor := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i := range res {
			res[i] ^= gfMul(gen[i], factor)
		}
	}
	return res
}

func qrBase(ver int) *qrCode {
	size := 17 + 4*ver
	q := &qrCode{size: size, dark: make([][]bool, size), function: make([][]bool, size)}
	for i := range q.dark {
		q.dark[i] = make([]bool, size)
		q.function[i] = make([]bool, size)
	}
	for i := 0; i < size; i++ {
		q.set(6, i, i%2 == 0)
		q.set(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {size - 4, 3}, {3, size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := c[0]+dx, c[1]+dy
				if x < 0 || y < 0 || x >= size || y >= size {
					continue
				}
				d := max(abs(dx), abs(dy))
				q.set(x, y, d != 2 && d != 4)
			}
		}
	}
	al := qrVersionsM[ver].align
	for i, ax := range al {
		for j, ay := range al {
			if (i == 0 && j == 0) || (i == 0 && j == len(al)-1) || (i == len(al)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					q.set(ax+dx, ay+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	q.drawFormat(0) // reserve the format areas
	if ver >= 7 {
		rem := ver
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := ver<<12 | rem
		for i := 0; i < 18; i++ {
			bit := bits>>uint(i)&1 == 1
			a, b := size-11+i%3, i/3
			q.set(a, b, bit)
			q.set(b, a, bit)
		}
	}
	return q
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// drawFormat writes the format bits for level M and mask.
func (q *qrCode) drawFormat(mask int) {
	data := 0<<3 | mask // level M is 00
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>uint(i)&1 == 1 }
	for i := 0; i <= 5; i++ {
		q.set(8, i, bit(i))
	}
	q.set(8, 7, bit(6))
	q.set(8, 8, bit(7))
	q.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		q.set(14-i, 8, bit(i))
	}
	for i := 0; i < 8; i++ {
		q.set(q.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		q.set(8, q.size-15+i, bit(i))
	}
	q.set(8, q.size-8, true)
}

func (q *qrCode) drawCodewords(data []byte) {
	i := 0
	for right := q.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < q.size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = q.size - 1 - vert
				}
				if !q.function[y][x] && i < len(data)*8 {
					q.dark[y][x] = data[i>>3]>>uint(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func (q *qrCode) applyMask(mask int) {
	for y := 0; y < q.size; y++ {
		for x := 0; x < q.size; x++ {
			var inv bool
			switch mask {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv && !q.function[y][x] {
				q.dark[y][x] = !q.dark[y][x]
			}
		}
	}
}

// penalty scores a masked symbol (lower is better), per the standard's four
// rules. Any mask decodes; this only picks the easiest one to scan.
func (q *qrCode) penalty() int {
	n, p := q.size, 0
	at := func(x, y int, col bool) bool {
		if col {
			return q.dark[x][y]
		}
		return q.dark[y][x]
	}
	for _, col := range []bool{false, true} {
		for a := 0; a < n; a++ {
			run := 1
			for b := 1; b < n; b++ {
				if at(b, a, col) == at(b-1, a, col) {
					run++
					if run == 5 {
						p += 3
					} else if run > 5 {
						p++
					}
				} else {
					run = 1
				}
			}
			// 1:1:3:1:1 finder-like patterns with four light modules on a side.
			for b := 0; b+7 <= n; b++ {
				if at(b, a, col) && !at(b+1, a, col) && at(b+2, a, col) && at(b+3, a, col) && at(b+4, a, col) &&
					!at(b+5, a, col) && at(b+6, a, col) {
					light := func(from, to int) bool {
						for k := from; k < to; k++ {
							if k >= 0 && k < n && at(k, a, col) {
								return false
							}
						}
						return true
					}
					if light(b-4, b) || light(b+7, b+11) {
						p += 40
					}
				}
			}
		}
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if q.dark[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				c := q.dark[y][x]
				if c == q.dark[y][x+1] && c == q.dark[y+1][x] && c == q.dark[y+1][x+1] {
					p += 3
				}
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10) + total - 1) / total
	return p + max(k-1, 0)*10
}
